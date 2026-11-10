using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Avalonia;
using Avalonia.Media.Imaging;
using Avalonia.Platform;
using Avalonia.Threading;
using ClassIsland.Core;
using Microsoft.Extensions.Logging;

namespace MiniClassIsland.ExtendManagement.Services.Handlers;

/// <summary>
/// [第二级高敏受控能力] 远程协助与终端控制处理器（remote.*）。
/// 每项能力均需客户端本地单独开启对应开关后方可执行：
/// - remote.exec_code       -> AllowExecuteCode
/// - remote.screenshot      -> AllowScreenshot
/// - remote.simulate_click  -> AllowSimulateClick
/// - remote.process_list    -> AllowGetProcessList
/// </summary>
public sealed class RemoteControlCommandHandler(ILogger<RemoteControlCommandHandler> logger)
{
    public async Task<JsonElement> ExecuteAsync(string action, JsonElement payload)
    {
        var normalized = action.Trim().ToLowerInvariant();
        return normalized switch
        {
            "remote.exec_code" or "remote.exec_command" => await ExecuteArbitraryCodeAsync(payload),
            "remote.screenshot" => await CaptureScreenshotAsync(payload),
            "remote.simulate_click" => await SimulateMouseClickAsync(payload),
            "remote.process_list" => await GetProcessListAsync(payload),
            _ => throw new NotSupportedException($"不支持的远程控制指令：{action}")
        };
    }

    #region 1. 执行任意代码 (remote.exec_code)

    private async Task<JsonElement> ExecuteArbitraryCodeAsync(JsonElement payload)
    {
        var command = payload.TryGetProperty("command", out var cmdProp)
            ? cmdProp.GetString()
            : payload.TryGetProperty("code", out var codeProp)
                ? codeProp.GetString()
                : null;

        if (string.IsNullOrWhiteSpace(command))
        {
            throw new ArgumentException("remote.exec_code 需要提供非空的 command 或 code 字段。");
        }

        var shell = payload.TryGetProperty("shell", out var shProp) && !string.IsNullOrWhiteSpace(shProp.GetString())
            ? shProp.GetString()!.Trim().ToLowerInvariant()
            : OperatingSystem.IsWindows() ? "powershell" : "sh";

        var workingDir = payload.TryGetProperty("workingDirectory", out var wdProp) && !string.IsNullOrWhiteSpace(wdProp.GetString())
            ? wdProp.GetString()!
            : Environment.CurrentDirectory;

        var timeoutSeconds = payload.TryGetProperty("timeoutSeconds", out var toProp) && toProp.TryGetInt32(out var parsedTo)
            ? Math.Clamp(parsedTo, 1, 300)
            : 30;

        var maxOutputChars = payload.TryGetProperty("maxOutputChars", out var maxProp) && maxProp.TryGetInt32(out var parsedMax)
            ? Math.Clamp(parsedMax, 1024, 512_000)
            : 65536;

        var psi = BuildProcessStartInfo(shell, command, workingDir);
        var sw = Stopwatch.StartNew();
        using var proc = new Process { StartInfo = psi };
        var stdoutBuilder = new StringBuilder();
        var stderrBuilder = new StringBuilder();

        proc.OutputDataReceived += (_, e) =>
        {
            if (e.Data != null && stdoutBuilder.Length < maxOutputChars)
            {
                stdoutBuilder.AppendLine(e.Data);
            }
        };
        proc.ErrorDataReceived += (_, e) =>
        {
            if (e.Data != null && stderrBuilder.Length < maxOutputChars)
            {
                stderrBuilder.AppendLine(e.Data);
            }
        };

        logger.LogWarning("安全审计：正在执行集控远程指令（Shell={Shell}, Timeout={Timeout}s）。", shell, timeoutSeconds);
        proc.Start();
        proc.BeginOutputReadLine();
        proc.BeginErrorReadLine();

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(timeoutSeconds));
        var timedOut = false;
        try
        {
            await proc.WaitForExitAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            timedOut = true;
            try
            {
                proc.Kill(entireProcessTree: true);
            }
            catch
            {
                // Ignore kill errors
            }
        }

        sw.Stop();
        var stdout = stdoutBuilder.ToString();
        var stderr = stderrBuilder.ToString();
        if (stdout.Length > maxOutputChars) stdout = stdout[..maxOutputChars];
        if (stderr.Length > maxOutputChars) stderr = stderr[..maxOutputChars];

        return JsonSerializer.SerializeToElement(new
        {
            shell,
            exitCode = timedOut ? -1 : proc.ExitCode,
            timedOut,
            durationMs = sw.ElapsedMilliseconds,
            stdout,
            stderr
        });
    }

    private static ProcessStartInfo BuildProcessStartInfo(string shell, string command, string workingDir)
    {
        var psi = new ProcessStartInfo
        {
            WorkingDirectory = Directory.Exists(workingDir) ? workingDir : Environment.CurrentDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };

        switch (shell)
        {
            case "powershell" or "pwsh":
                psi.FileName = shell == "pwsh" ? "pwsh" : "powershell.exe";
                psi.ArgumentList.Add("-NoProfile");
                psi.ArgumentList.Add("-NonInteractive");
                psi.ArgumentList.Add("-Command");
                psi.ArgumentList.Add($"[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; {command}");
                break;

            case "cmd":
                psi.FileName = "cmd.exe";
                psi.Arguments = $"/d /s /c \"chcp 65001 >nul && {command}\"";
                break;

            case "bash":
                psi.FileName = "/bin/bash";
                psi.ArgumentList.Add("-c");
                psi.ArgumentList.Add(command);
                break;

            default:
                psi.FileName = "/bin/sh";
                psi.ArgumentList.Add("-c");
                psi.ArgumentList.Add(command);
                break;
        }

        return psi;
    }

    #endregion

    #region 2. 获取客户端屏幕截图 (remote.screenshot)

    private async Task<JsonElement> CaptureScreenshotAsync(JsonElement payload)
    {
        var displayIndex = payload.TryGetProperty("displayIndex", out var dProp) && dProp.TryGetInt32(out var idx)
            ? idx
            : -1;

        var scale = payload.TryGetProperty("scale", out var sProp) && sProp.TryGetDouble(out var sc)
            ? Math.Clamp(sc, 0.1, 1.0)
            : 1.0;

        // 获取目标屏幕的物理边界
        var bounds = await Dispatcher.UIThread.InvokeAsync(() =>
        {
            var screens = AppBase.Current.MainWindow?.Screens ?? FluentAvaloniaBridge.GetSafeOwnerWindow()?.Screens;
            if (screens == null || screens.All.Count == 0)
            {
                return new PixelRect(0, 0, 1920, 1080);
            }

            if (displayIndex >= 0 && displayIndex < screens.All.Count)
            {
                return screens.All[displayIndex].Bounds;
            }

            var primary = screens.Primary ?? screens.All[0];
            return primary.Bounds;
        });

        return await Task.Run(() =>
        {
            if (!OperatingSystem.IsWindows())
            {
                throw new PlatformNotSupportedException("当前系统环境暂不支持原生 GDI 屏幕捕获。");
            }

            var srcWidth = Math.Max(1, bounds.Width);
            var srcHeight = Math.Max(1, bounds.Height);
            var dstWidth = Math.Max(1, (int)Math.Round(srcWidth * scale));
            var dstHeight = Math.Max(1, (int)Math.Round(srcHeight * scale));

            var rawBgra = CaptureScreenRegionBgra32(bounds.X, bounds.Y, srcWidth, srcHeight);
            var finalBgra = (dstWidth == srcWidth && dstHeight == srcHeight)
                ? rawBgra
                : ResizeBgra32Bilinear(rawBgra, srcWidth, srcHeight, dstWidth, dstHeight);

            using var writeableBitmap = new WriteableBitmap(
                new PixelSize(dstWidth, dstHeight),
                new Vector(96, 96),
                PixelFormat.Bgra8888,
                AlphaFormat.Opaque);

            using (var fb = writeableBitmap.Lock())
            {
                var rowBytes = dstWidth * 4;
                for (var y = 0; y < dstHeight; y++)
                {
                    Marshal.Copy(finalBgra, y * rowBytes, fb.Address + y * fb.RowBytes, rowBytes);
                }
            }

            using var ms = new MemoryStream();
            writeableBitmap.Save(ms);
            var base64 = Convert.ToBase64String(ms.ToArray());

            logger.LogInformation("安全审计：已采集屏幕截图（{W}x{H}）。", dstWidth, dstHeight);
            return JsonSerializer.SerializeToElement(new
            {
                mimeType = "image/png",
                width = dstWidth,
                height = dstHeight,
                originalWidth = srcWidth,
                originalHeight = srcHeight,
                boundsX = bounds.X,
                boundsY = bounds.Y,
                imageBase64 = base64
            });
        });
    }

    private static byte[] CaptureScreenRegionBgra32(int x, int y, int width, int height)
    {
        var hScreenDc = GetDC(IntPtr.Zero);
        if (hScreenDc == IntPtr.Zero)
        {
            throw new InvalidOperationException("无法获取屏幕设备上下文。");
        }

        var hMemDc = IntPtr.Zero;
        var hBitmap = IntPtr.Zero;
        var hOld = IntPtr.Zero;
        try
        {
            hMemDc = CreateCompatibleDC(hScreenDc);
            hBitmap = CreateCompatibleBitmap(hScreenDc, width, height);
            hOld = SelectObject(hMemDc, hBitmap);

            const int SRCCOPY = 0x00CC0020;
            const int CAPTUREBLT = 0x40000000;
            if (!BitBlt(hMemDc, 0, 0, width, height, hScreenDc, x, y, SRCCOPY | CAPTUREBLT))
            {
                throw new InvalidOperationException("GDI BitBlt 屏幕捕获失败。");
            }

            var bmi = new BITMAPINFOHEADER
            {
                biSize = (uint)Marshal.SizeOf<BITMAPINFOHEADER>(),
                biWidth = width,
                biHeight = -height, // Top-down DIB
                biPlanes = 1,
                biBitCount = 32,
                biCompression = 0 // BI_RGB
            };

            var pixelBytes = new byte[width * height * 4];
            var lines = GetDIBits(hMemDc, hBitmap, 0, (uint)height, pixelBytes, ref bmi, 0);
            if (lines == 0)
            {
                throw new InvalidOperationException("读取屏幕位图像素失败。");
            }

            // 确保 Alpha 通道为 255
            for (var i = 3; i < pixelBytes.Length; i += 4)
            {
                pixelBytes[i] = 255;
            }

            return pixelBytes;
        }
        finally
        {
            if (hOld != IntPtr.Zero && hMemDc != IntPtr.Zero) SelectObject(hMemDc, hOld);
            if (hBitmap != IntPtr.Zero) DeleteObject(hBitmap);
            if (hMemDc != IntPtr.Zero) DeleteDC(hMemDc);
            ReleaseDC(IntPtr.Zero, hScreenDc);
        }
    }

    private static byte[] ResizeBgra32Bilinear(byte[] src, int srcW, int srcH, int dstW, int dstH)
    {
        var dst = new byte[dstW * dstH * 4];
        var xRatio = (double)srcW / dstW;
        var yRatio = (double)srcH / dstH;

        for (var y = 0; y < dstH; y++)
        {
            var srcY = Math.Min(srcH - 1, (int)(y * yRatio));
            for (var x = 0; x < dstW; x++)
            {
                var srcX = Math.Min(srcW - 1, (int)(x * xRatio));
                var srcIdx = (srcY * srcW + srcX) * 4;
                var dstIdx = (y * dstW + x) * 4;
                dst[dstIdx] = src[srcIdx];
                dst[dstIdx + 1] = src[srcIdx + 1];
                dst[dstIdx + 2] = src[srcIdx + 2];
                dst[dstIdx + 3] = 255;
            }
        }
        return dst;
    }

    #endregion

    #region 3. 模拟鼠标点击指令 (remote.simulate_click)

    private async Task<JsonElement> SimulateMouseClickAsync(JsonElement payload)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("当前系统环境暂不支持原生 Win32 鼠标输入注入。");
        }

        var buttonType = payload.TryGetProperty("button", out var bProp) && !string.IsNullOrWhiteSpace(bProp.GetString())
            ? bProp.GetString()!.Trim().ToLowerInvariant()
            : "left";

        var clickType = payload.TryGetProperty("clickType", out var cProp) && !string.IsNullOrWhiteSpace(cProp.GetString())
            ? cProp.GetString()!.Trim().ToLowerInvariant()
            : "single";

        var screenBounds = await Dispatcher.UIThread.InvokeAsync(() =>
        {
            var screens = AppBase.Current.MainWindow?.Screens ?? FluentAvaloniaBridge.GetSafeOwnerWindow()?.Screens;
            var primary = screens?.Primary ?? screens?.All.FirstOrDefault();
            return primary?.Bounds ?? new PixelRect(0, 0, 1920, 1080);
        });

        int targetX, targetY;
        if (payload.TryGetProperty("normalizedX", out var nxProp) &&
            payload.TryGetProperty("normalizedY", out var nyProp) &&
            nxProp.TryGetDouble(out var nx) &&
            nyProp.TryGetDouble(out var ny))
        {
            targetX = screenBounds.X + (int)Math.Round(Math.Clamp(nx, 0.0, 1.0) * screenBounds.Width);
            targetY = screenBounds.Y + (int)Math.Round(Math.Clamp(ny, 0.0, 1.0) * screenBounds.Height);
        }
        else if (payload.TryGetProperty("x", out var xProp) &&
                 payload.TryGetProperty("y", out var yProp) &&
                 xProp.TryGetInt32(out var px) &&
                 yProp.TryGetInt32(out var py))
        {
            targetX = px;
            targetY = py;
        }
        else
        {
            throw new ArgumentException("remote.simulate_click 需要提供像素坐标 (x, y) 或归一化坐标 (normalizedX, normalizedY)。");
        }

        SetCursorPos(targetX, targetY);

        if (clickType != "move")
        {
            var (downFlag, upFlag) = buttonType switch
            {
                "right" => (MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_RIGHTUP),
                "middle" => (MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP),
                _ => (MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP)
            };

            var repeatCount = clickType == "double" ? 2 : 1;
            for (var i = 0; i < repeatCount; i++)
            {
                if (clickType == "down")
                {
                    mouse_event(downFlag, 0, 0, 0, UIntPtr.Zero);
                }
                else if (clickType == "up")
                {
                    mouse_event(upFlag, 0, 0, 0, UIntPtr.Zero);
                }
                else
                {
                    mouse_event(downFlag, 0, 0, 0, UIntPtr.Zero);
                    await Task.Delay(35);
                    mouse_event(upFlag, 0, 0, 0, UIntPtr.Zero);
                }

                if (i + 1 < repeatCount)
                {
                    await Task.Delay(60);
                }
            }
        }

        logger.LogWarning("安全审计：已执行集控模拟点击指令（坐标={X},{Y}, 按钮={Button}, 类型={ClickType}）。",
            targetX, targetY, buttonType, clickType);

        return JsonSerializer.SerializeToElement(new
        {
            executed = true,
            x = targetX,
            y = targetY,
            button = buttonType,
            clickType
        });
    }

    #endregion

    #region 4. 获取客户端进程清单 (remote.process_list)

    private async Task<JsonElement> GetProcessListAsync(JsonElement payload)
    {
        var filterKeyword = payload.TryGetProperty("keyword", out var kwProp)
            ? kwProp.GetString()?.Trim()
            : null;

        return await Task.Run(() =>
        {
            var processes = Process.GetProcesses();
            var list = new List<object>(processes.Length);

            foreach (var p in processes)
            {
                try
                {
                    var name = p.ProcessName;
                    var title = string.Empty;
                    try
                    {
                        title = p.MainWindowTitle;
                    }
                    catch
                    {
                        // Ignore
                    }

                    if (!string.IsNullOrWhiteSpace(filterKeyword) &&
                        !name.Contains(filterKeyword, StringComparison.OrdinalIgnoreCase) &&
                        !title.Contains(filterKeyword, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    string? exePath = null;
                    try
                    {
                        exePath = p.MainModule?.FileName;
                    }
                    catch
                    {
                        // 系统进程无权限访问 MainModule 时安全降级
                    }

                    DateTimeOffset? startTime = null;
                    try
                    {
                        startTime = new DateTimeOffset(p.StartTime.ToUniversalTime());
                    }
                    catch
                    {
                        // Ignore
                    }

                    list.Add(new
                    {
                        pid = p.Id,
                        name,
                        mainWindowTitle = title,
                        executablePath = exePath,
                        workingSetBytes = p.WorkingSet64,
                        sessionId = p.SessionId,
                        responding = p.Responding,
                        startTimeUtc = startTime
                    });
                }
                catch
                {
                    // Skip terminated process
                }
                finally
                {
                    p.Dispose();
                }
            }

            return JsonSerializer.SerializeToElement(new
            {
                collectedAtUtc = DateTimeOffset.UtcNow,
                totalCount = list.Count,
                processes = list
            });
        });
    }

    #endregion

    #region Win32 GDI32 & User32 P/Invoke

    [StructLayout(LayoutKind.Sequential)]
    private struct BITMAPINFOHEADER
    {
        public uint biSize;
        public int biWidth;
        public int biHeight;
        public ushort biPlanes;
        public ushort biBitCount;
        public uint biCompression;
        public uint biSizeImage;
        public int biXPelsPerMeter;
        public int biYPelsPerMeter;
        public uint biClrUsed;
        public uint biClrImportant;
    }

    [DllImport("user32.dll")]
    private static extern IntPtr GetDC(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern int ReleaseDC(IntPtr hWnd, IntPtr hDC);

    [DllImport("gdi32.dll")]
    private static extern IntPtr CreateCompatibleDC(IntPtr hdc);

    [DllImport("gdi32.dll")]
    private static extern IntPtr CreateCompatibleBitmap(IntPtr hdc, int nWidth, int nHeight);

    [DllImport("gdi32.dll")]
    private static extern IntPtr SelectObject(IntPtr hdc, IntPtr hgdiobj);

    [DllImport("gdi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool BitBlt(IntPtr hdcDest, int nXDest, int nYDest, int nWidth, int nHeight, IntPtr hdcSrc, int nXSrc, int nYSrc, int dwRop);

    [DllImport("gdi32.dll")]
    private static extern int GetDIBits(IntPtr hdc, IntPtr hbmp, uint uStartScan, uint cScanLines, [Out] byte[] lpvBits, ref BITMAPINFOHEADER lpbmi, uint uUsage);

    [DllImport("gdi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeleteObject(IntPtr hObject);

    [DllImport("gdi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeleteDC(IntPtr hdc);

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetCursorPos(int X, int Y);

    [DllImport("user32.dll")]
    private static extern void mouse_event(uint dwFlags, uint dx, uint dy, uint dwData, UIntPtr dwExtraInfo);

    private const uint MOUSEEVENTF_LEFTDOWN = 0x0002;
    private const uint MOUSEEVENTF_LEFTUP = 0x0004;
    private const uint MOUSEEVENTF_RIGHTDOWN = 0x0008;
    private const uint MOUSEEVENTF_RIGHTUP = 0x0010;
    private const uint MOUSEEVENTF_MIDDLEDOWN = 0x0020;
    private const uint MOUSEEVENTF_MIDDLEUP = 0x0040;

    #endregion
}
