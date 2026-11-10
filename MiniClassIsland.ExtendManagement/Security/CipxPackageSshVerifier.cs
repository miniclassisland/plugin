using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace MiniClassIsland.ExtendManagement.Security;

/// <summary>
/// 基于 GitHub 提交使用的 SSH-Ed25519 公钥（SSHSIG 协议）的 .cipx 插件包数字签名与完整性校验器。
/// 支持两种不破坏 ClassIsland 原生 ZIP 解压器的内嵌签名方案：
/// 1. 方案 A（包内嵌入式签名清单 `SIGNATURE.json` + `SIGNATURE.sshsig`）：对包内除签名文件外的所有文件按确定性顺序计算 SHA-256 清单，并使用 `ssh-keygen -Y sign` 生成标准 SSHSIG (Ed25519) 签名；
/// 2. 方案 B（ZIP Central Directory Comment 尾部内嵌签名块）：在 ZIP 归档注释区（EOCD Comment）内追加 `MCI-SSHSIG-V1:` 签名载荷，实现单文件自包含验签。
/// </summary>
public static class CipxPackageSshVerifier
{
    /// <summary>
    /// 固化受信任的开发者 GitHub 提交签名 SSH-Ed25519 公钥（源自本地 git user.signingkey: ~/.ssh/id_ed25519.pub）。
    /// </summary>
    public const string TrustedDeveloperSshPublicKey =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGhzUQsvb6T9YCSVY77miji53RDCFkb4QJnvd9ONEyW1 admin@minisvc.com";

    /// <summary>
    /// SSHSIG 签名命名空间（防止跨协议签名重放）。
    /// </summary>
    public const string SshSignatureNamespace = "miniclassisland.cipx.v1";

    public const string SignatureManifestEntryName = "SIGNATURE.json";
    public const string SignatureSshSigEntryName = "SIGNATURE.sshsig";
    public const string ZipCommentMagicPrefix = "MCI-SSHSIG-V1:";

    private static readonly byte[] TrustedEd25519PublicKeyBytes = ExtractEd25519PublicKeyFromAuthorizedKey(TrustedDeveloperSshPublicKey);

    public sealed class CipxSignatureManifest
    {
        [JsonPropertyName("schema")]
        public string Schema { get; set; } = "miniclassisland.cipx.manifest.v1";

        [JsonPropertyName("pluginId")]
        public string PluginId { get; set; } = SelfProtectionService.PluginId;

        [JsonPropertyName("version")]
        public string Version { get; set; } = string.Empty;

        [JsonPropertyName("signerPublicKey")]
        public string SignerPublicKey { get; set; } = string.Empty;

        [JsonPropertyName("signedAtUtc")]
        public string SignedAtUtc { get; set; } = string.Empty;

        [JsonPropertyName("files")]
        public SortedDictionary<string, string> Files { get; set; } = new(StringComparer.Ordinal);
    }

    public sealed class ZipCommentEnvelope
    {
        [JsonPropertyName("manifest")]
        public string ManifestBase64 { get; set; } = string.Empty;

        [JsonPropertyName("sshsig")]
        public string SshSigArmored { get; set; } = string.Empty;
    }

    /// <summary>
    /// 校验一个已解压的插件安装目录（如 Plugins/org.miniopensource.miniclassisland.extendmanagement）是否具有合法的 SSH-Ed25519 签名。
    /// </summary>
    public static (bool IsValid, string Reason, string? Version) VerifyInstalledPluginDirectory(string pluginFolderPath)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(pluginFolderPath) || !Directory.Exists(pluginFolderPath))
            {
                return (false, "插件目录不存在。", null);
            }

            var manifestPath = Path.Combine(pluginFolderPath, SignatureManifestEntryName);
            var sigPath = Path.Combine(pluginFolderPath, SignatureSshSigEntryName);
            if (!File.Exists(manifestPath) || !File.Exists(sigPath))
            {
                return (false, "插件目录缺少 SIGNATURE.json 或 SIGNATURE.sshsig 签名文件。", null);
            }

            var manifestBytes = File.ReadAllBytes(manifestPath);
            var sshSigArmored = File.ReadAllText(sigPath, Encoding.UTF8);

            var (sigOk, sigErr) = VerifySshSigRaw(manifestBytes, sshSigArmored, SshSignatureNamespace, TrustedEd25519PublicKeyBytes);
            if (!sigOk)
            {
                return (false, $"已安装目录 SSH-Ed25519 签名校验失败：{sigErr}", null);
            }

            var manifest = JsonSerializer.Deserialize<CipxSignatureManifest>(manifestBytes);
            if (manifest == null || manifest.Files == null || manifest.Files.Count == 0)
            {
                return (false, "签名清单内容为空或格式无效。", null);
            }

            if (!string.Equals(manifest.PluginId, SelfProtectionService.PluginId, StringComparison.OrdinalIgnoreCase))
            {
                return (false, $"签名清单插件 ID 不匹配：{manifest.PluginId}", null);
            }

            foreach (var (relativePath, expectedHashHex) in manifest.Files)
            {
                var fullPath = Path.Combine(pluginFolderPath, relativePath.Replace('/', Path.DirectorySeparatorChar));
                if (!File.Exists(fullPath))
                {
                    return (false, $"受签名保护的核心文件缺失：{relativePath}", manifest.Version);
                }

                var actualBytes = File.ReadAllBytes(fullPath);
                var actualHashHex = Convert.ToHexString(SHA256.HashData(actualBytes)).ToLowerInvariant();
                if (!string.Equals(actualHashHex, expectedHashHex, StringComparison.OrdinalIgnoreCase))
                {
                    return (false, $"文件哈希与 SSH 签名清单不一致：{relativePath}", manifest.Version);
                }
            }

            return (true, "OK", manifest.Version);
        }
        catch (Exception ex)
        {
            return (false, $"校验已安装插件目录签名异常：{ex.Message}", null);
        }
    }

    /// <summary>
    /// 校验一个 .cipx 插件包文件是否包含本插件且具有合法的开发者 SSH-Ed25519 数字签名。
    /// </summary>
    public static (bool IsSelfPluginPackage, bool IsSignatureValid, string Reason, string? Version) InspectAndVerifyCipxPackage(string cipxFilePath)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(cipxFilePath) || !File.Exists(cipxFilePath))
            {
                return (false, false, "文件不存在。", null);
            }

            using var fs = new FileStream(cipxFilePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var archive = new ZipArchive(fs, ZipArchiveMode.Read, leaveOpen: true);

            // 1. 判断该 .cipx 是否针对本插件（通过文件名、manifest.yml 或包含 MiniClassIsland.ExtendManagement.dll）
            var isSelfPackage = Path.GetFileNameWithoutExtension(cipxFilePath)
                .Equals(SelfProtectionService.PluginId, StringComparison.OrdinalIgnoreCase);

            var manifestYmlEntry = archive.GetEntry("manifest.yml");
            if (manifestYmlEntry != null)
            {
                using var reader = new StreamReader(manifestYmlEntry.Open(), Encoding.UTF8);
                var ymlText = reader.ReadToEnd();
                if (ymlText.Contains(SelfProtectionService.PluginId, StringComparison.OrdinalIgnoreCase))
                {
                    isSelfPackage = true;
                }
            }

            if (archive.Entries.Any(e => string.Equals(e.FullName, "MiniClassIsland.ExtendManagement.dll", StringComparison.OrdinalIgnoreCase)))
            {
                isSelfPackage = true;
            }

            if (!isSelfPackage)
            {
                return (false, true, "非本插件安装包，放行。", null);
            }

            // 2. 提取包内嵌入式 SIGNATURE.json + SIGNATURE.sshsig（或从 ZIP Comment 尾部签名块提取）
            byte[]? manifestBytes = null;
            string? sshSigArmored = null;

            var sigManifestEntry = archive.GetEntry(SignatureManifestEntryName);
            var sigSshEntry = archive.GetEntry(SignatureSshSigEntryName);
            if (sigManifestEntry != null && sigSshEntry != null)
            {
                using (var ms = new MemoryStream())
                {
                    using var s = sigManifestEntry.Open();
                    s.CopyTo(ms);
                    manifestBytes = ms.ToArray();
                }
                using (var sr = new StreamReader(sigSshEntry.Open(), Encoding.UTF8))
                {
                    sshSigArmored = sr.ReadToEnd();
                }
            }
            else if (TryExtractZipCommentSignature(fs, out var commentManifestBytes, out var commentSshSig))
            {
                manifestBytes = commentManifestBytes;
                sshSigArmored = commentSshSig;
            }

            if (manifestBytes == null || string.IsNullOrWhiteSpace(sshSigArmored))
            {
                return (true, false, "插件包缺少开发者 SSH-Ed25519 数字签名（SIGNATURE.json / SIGNATURE.sshsig）。", null);
            }

            // 3. 验证 SSHSIG Ed25519 数字签名
            var (sigOk, sigErr) = VerifySshSigRaw(manifestBytes, sshSigArmored, SshSignatureNamespace, TrustedEd25519PublicKeyBytes);
            if (!sigOk)
            {
                return (true, false, $"插件包 SSH-Ed25519 签名验证未通过：{sigErr}", null);
            }

            var manifest = JsonSerializer.Deserialize<CipxSignatureManifest>(manifestBytes);
            if (manifest == null || manifest.Files == null || manifest.Files.Count == 0)
            {
                return (true, false, "插件包签名清单格式无效。", null);
            }

            if (!string.Equals(manifest.PluginId, SelfProtectionService.PluginId, StringComparison.OrdinalIgnoreCase))
            {
                return (true, false, $"插件包签名清单 PluginId 不匹配：{manifest.PluginId}", null);
            }

            // 4. 校验包内所有实际业务文件与签名清单必须严格 1:1 匹配（不允许篡改、缺失或额外夹带未签名的文件）
            var actualFileHashes = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var entry in archive.Entries)
            {
                if (string.IsNullOrEmpty(entry.Name) && entry.FullName.EndsWith('/'))
                {
                    continue;
                }

                var normName = entry.FullName.Replace('\\', '/');
                if (string.Equals(normName, SignatureManifestEntryName, StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(normName, SignatureSshSigEntryName, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                using var entryStream = entry.Open();
                var hashHex = Convert.ToHexString(SHA256.HashData(entryStream)).ToLowerInvariant();
                actualFileHashes[normName] = hashHex;
            }

            if (actualFileHashes.Count != manifest.Files.Count)
            {
                return (true, false, $"插件包内文件数量（{actualFileHashes.Count}）与签名清单记录数（{manifest.Files.Count}）不一致，疑似被夹带或删减文件。", manifest.Version);
            }

            foreach (var (fileName, expectedHash) in manifest.Files)
            {
                if (!actualFileHashes.TryGetValue(fileName, out var actualHash))
                {
                    return (true, false, $"插件包缺失受签名保护的文件：{fileName}", manifest.Version);
                }

                if (!string.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase))
                {
                    return (true, false, $"插件包文件 {fileName} 哈希校验失败（文件已被篡改）。", manifest.Version);
                }
            }

            return (true, true, "SSH-Ed25519 签名与包内全量文件哈希校验通过。", manifest.Version);
        }
        catch (Exception ex)
        {
            return (true, false, $"解析或校验 .cipx 签名时发生异常：{ex.Message}", null);
        }
    }

    /// <summary>
    /// 解析并验证 OpenSSH `ssh-keygen -Y sign` 生成的 `-----BEGIN SSH SIGNATURE-----` (SSHSIG) 签名。
    /// 遵循 OpenSSH PROTOCOL.sshsig 规范：
    /// 1. Blob 头为 "SSHSIG" (6 bytes) + version (uint32 = 1) + publickey (string) + namespace (string) + reserved (string) + hash_algorithm (string) + signature (string)
    /// 2. 待签名的数据包装结构为：
    ///    "SSHSIG" (6 bytes, 无长度前缀) + namespace (string) + reserved (string) + hash_algorithm (string) + H(message) (string)
    /// </summary>
    public static (bool IsValid, string ErrorMessage) VerifySshSigRaw(
        byte[] messageBytes,
        string armoredSignature,
        string expectedNamespace,
        byte[] trustedEd25519PubKey32Bytes)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(armoredSignature))
            {
                return (false, "SSHSIG 签名为空。");
            }

            var lines = armoredSignature
                .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
                .Select(l => l.Trim())
                .Where(l => !l.StartsWith("-----BEGIN ", StringComparison.Ordinal) &&
                            !l.StartsWith("-----END ", StringComparison.Ordinal))
                .ToArray();

            if (lines.Length == 0)
            {
                return (false, "未找到有效的 SSH SIGNATURE Base64 内容。");
            }

            var blob = Convert.FromBase64String(string.Concat(lines));
            var offset = 0;

            // 1. Magic preamble: "SSHSIG" (6 bytes)
            if (blob.Length < 10 || Encoding.ASCII.GetString(blob, 0, 6) != "SSHSIG")
            {
                return (false, "SSHSIG 魔数头无效。");
            }
            offset += 6;

            // 2. Version: uint32 (must be 1)
            var version = BinaryPrimitives.ReadUInt32BigEndian(blob.AsSpan(offset, 4));
            offset += 4;
            if (version != 1)
            {
                return (false, $"不支持的 SSHSIG 版本：{version}");
            }

            // 3. Public key blob (ssh-ed25519)
            var pubKeyBlob = ReadSshBytes(blob, ref offset);
            var pkOffset = 0;
            var keyType = ReadSshString(pubKeyBlob, ref pkOffset);
            if (!string.Equals(keyType, "ssh-ed25519", StringComparison.Ordinal))
            {
                return (false, $"不支持的公钥算法：{keyType}（仅允许 ssh-ed25519）");
            }
            var rawPubKeyInSig = ReadSshBytes(pubKeyBlob, ref pkOffset);
            if (rawPubKeyInSig.Length != 32 ||
                !CryptographicOperations.FixedTimeEquals(rawPubKeyInSig, trustedEd25519PubKey32Bytes))
            {
                return (false, "签名公钥与受信任的开发者 GitHub SSH 公钥不匹配。");
            }

            // 4. Namespace
            var sigNamespace = ReadSshString(blob, ref offset);
            if (!string.Equals(sigNamespace, expectedNamespace, StringComparison.Ordinal))
            {
                return (false, $"SSHSIG 命名空间不匹配（预期：{expectedNamespace}，实际：{sigNamespace}）。");
            }

            // 5. Reserved
            var reserved = ReadSshBytes(blob, ref offset);

            // 6. Hash algorithm ("sha512" or "sha256")
            var hashAlgorithm = ReadSshString(blob, ref offset);
            byte[] messageHash;
            if (string.Equals(hashAlgorithm, "sha512", StringComparison.OrdinalIgnoreCase))
            {
                messageHash = SHA512.HashData(messageBytes);
            }
            else if (string.Equals(hashAlgorithm, "sha256", StringComparison.OrdinalIgnoreCase))
            {
                messageHash = SHA256.HashData(messageBytes);
            }
            else
            {
                return (false, $"不支持的 SSHSIG 摘要算法：{hashAlgorithm}");
            }

            // 7. Signature blob
            var signatureBlob = ReadSshBytes(blob, ref offset);
            var sigOffset = 0;
            var sigKeyType = ReadSshString(signatureBlob, ref sigOffset);
            if (!string.Equals(sigKeyType, "ssh-ed25519", StringComparison.Ordinal))
            {
                return (false, $"不支持的签名算法：{sigKeyType}");
            }
            var rawSignature64 = ReadSshBytes(signatureBlob, ref sigOffset);
            if (rawSignature64.Length != 64)
            {
                return (false, $"Ed25519 签名长度无效：{rawSignature64.Length}");
            }

            // 8. 构造 SSHSIG Signed-Data Wrapper 并使用 BouncyCastle Ed25519Signer 校验
            using var signedDataStream = new MemoryStream();
            signedDataStream.Write("SSHSIG"u8);
            WriteSshString(signedDataStream, sigNamespace);
            WriteSshBytes(signedDataStream, reserved);
            WriteSshString(signedDataStream, hashAlgorithm);
            WriteSshBytes(signedDataStream, messageHash);
            var signedData = signedDataStream.ToArray();

            var verifier = new Ed25519Signer();
            verifier.Init(forSigning: false, new Ed25519PublicKeyParameters(trustedEd25519PubKey32Bytes, 0));
            verifier.BlockUpdate(signedData, 0, signedData.Length);

            if (!verifier.VerifySignature(rawSignature64))
            {
                return (false, "Ed25519 密码学签名验证失败。");
            }

            return (true, "OK");
        }
        catch (Exception ex)
        {
            return (false, $"解析 SSHSIG 结构异常：{ex.Message}");
        }
    }

    private static bool TryExtractZipCommentSignature(Stream zipStream, out byte[]? manifestBytes, out string? sshSigArmored)
    {
        manifestBytes = null;
        sshSigArmored = null;
        try
        {
            var searchLen = (int)Math.Min(zipStream.Length, 65535 + 22);
            var buffer = new byte[searchLen];
            zipStream.Seek(zipStream.Length - searchLen, SeekOrigin.Begin);
            var read = zipStream.Read(buffer, 0, searchLen);

            // 从尾部向前查找 EOCD 签名 (0x06054b50 -> 50 4B 05 06)
            for (var i = read - 22; i >= 0; i--)
            {
                if (buffer[i] == 0x50 && buffer[i + 1] == 0x4B && buffer[i + 2] == 0x05 && buffer[i + 3] == 0x06)
                {
                    var commentLen = BinaryPrimitives.ReadUInt16LittleEndian(buffer.AsSpan(i + 20, 2));
                    if (commentLen > 0 && i + 22 + commentLen <= read)
                    {
                        var commentText = Encoding.UTF8.GetString(buffer, i + 22, commentLen);
                        var idx = commentText.IndexOf(ZipCommentMagicPrefix, StringComparison.Ordinal);
                        if (idx >= 0)
                        {
                            var b64Payload = commentText[(idx + ZipCommentMagicPrefix.Length)..].Trim();
                            var envelopeJson = Encoding.UTF8.GetString(Convert.FromBase64String(b64Payload));
                            var env = JsonSerializer.Deserialize<ZipCommentEnvelope>(envelopeJson);
                            if (env != null && !string.IsNullOrWhiteSpace(env.ManifestBase64) && !string.IsNullOrWhiteSpace(env.SshSigArmored))
                            {
                                manifestBytes = Convert.FromBase64String(env.ManifestBase64);
                                sshSigArmored = env.SshSigArmored;
                                return true;
                            }
                        }
                    }
                    break;
                }
            }
        }
        catch
        {
            // Ignore
        }
        return false;
    }

    public static byte[] ExtractEd25519PublicKeyFromAuthorizedKey(string authorizedKeyLine)
    {
        var parts = authorizedKeyLine.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2 || !string.Equals(parts[0], "ssh-ed25519", StringComparison.Ordinal))
        {
            throw new ArgumentException("无效的 ssh-ed25519 公钥格式。");
        }

        var blob = Convert.FromBase64String(parts[1]);
        var offset = 0;
        var keyType = ReadSshString(blob, ref offset);
        if (!string.Equals(keyType, "ssh-ed25519", StringComparison.Ordinal))
        {
            throw new ArgumentException($"公钥类型不匹配：{keyType}");
        }

        var pubKeyBytes = ReadSshBytes(blob, ref offset);
        if (pubKeyBytes.Length != 32)
        {
            throw new ArgumentException($"Ed25519 公钥长度无效：{pubKeyBytes.Length}");
        }

        return pubKeyBytes;
    }

    private static string ReadSshString(byte[] buffer, ref int offset)
    {
        var bytes = ReadSshBytes(buffer, ref offset);
        return Encoding.UTF8.GetString(bytes);
    }

    private static byte[] ReadSshBytes(byte[] buffer, ref int offset)
    {
        if (offset + 4 > buffer.Length)
        {
            throw new InvalidDataException("SSH 数据流意外结束（读取长度头失败）。");
        }

        var len = BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(offset, 4));
        offset += 4;
        if (len > int.MaxValue || offset + (int)len > buffer.Length)
        {
            throw new InvalidDataException($"SSH 数据块长度越界：{len}");
        }

        var result = new byte[(int)len];
        Buffer.BlockCopy(buffer, offset, result, 0, (int)len);
        offset += (int)len;
        return result;
    }

    private static void WriteSshString(Stream stream, string value)
    {
        WriteSshBytes(stream, Encoding.UTF8.GetBytes(value));
    }

    private static void WriteSshBytes(Stream stream, byte[] bytes)
    {
        Span<byte> lenBuf = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(lenBuf, (uint)bytes.Length);
        stream.Write(lenBuf);
        stream.Write(bytes);
    }
}
