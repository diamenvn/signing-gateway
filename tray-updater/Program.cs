using System.ComponentModel;
using System.Diagnostics;
using System.Net.Http;
using System.Reflection;
using System.Text.Json;
using SigningGateway.Updates;

internal static class Program
{
    [STAThread]
    static void Main()
    {
        using var mutex = new Mutex(true, @"Local\SigningGateway.UpdateTray", out bool created);
        if (!created) return;
        ApplicationConfiguration.Initialize();
        Application.Run(new UpdateTray());
    }
}

sealed record Deferred(string Version, DateTimeOffset Until);

sealed class UpdateTray : ApplicationContext
{
    readonly NotifyIcon icon;
    readonly System.Windows.Forms.Timer timer = new() { Interval = 60000 };
    readonly HttpClient http = new() { Timeout = Timeout.InfiniteTimeSpan };
    readonly UpdateClient client;
    readonly string current = Assembly.GetExecutingAssembly().GetCustomAttribute<AssemblyInformationalVersionAttribute>()!.InformationalVersion.Split('+')[0];
    readonly string stateDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SigningGateway", "Updates");
    DateTimeOffset nextCheck = DateTimeOffset.MinValue;
    DateTimeOffset notifyAfter = DateTimeOffset.MinValue;
    Release? latest;
    Form? dialog;
    bool busy;
    bool installing;
    bool startupCheckPending = true;

    public UpdateTray()
    {
        client = new UpdateClient(http);
        // Setup may terminate the old tray before it can remove its downloaded file.
        try
        {
            if (Directory.Exists(stateDir))
                foreach (string file in Directory.EnumerateFiles(stateDir, "*.exe"))
                    if (Guid.TryParse(Path.GetFileNameWithoutExtension(file), out _) && File.GetLastWriteTimeUtc(file) < DateTime.UtcNow.AddDays(-7))
                        try { File.Delete(file); } catch { }
        }
        catch { }
        var menu = new ContextMenuStrip();
        menu.Items.Add($"Signing Gateway {current}").Enabled = false;
        menu.Items.Add("Kiểm tra cập nhật", null, async (_, _) => await Check(true));
        menu.Items.Add("Xem bản cập nhật", null, (_, _) => ShowUpdate());
        menu.Items.Add("Thoát thông báo cập nhật", null, (_, _) => { if (!installing) ExitThread(); });
        string iconFile = Path.Combine(AppContext.BaseDirectory, "vnpt.ico");
        icon = new NotifyIcon { Text = $"Signing Gateway {current}", Visible = true,
            Icon = File.Exists(iconFile) ? new Icon(iconFile) : SystemIcons.Application, ContextMenuStrip = menu };
        icon.BalloonTipClicked += (_, _) => ShowUpdate();
        icon.DoubleClick += async (_, _) => { if (latest != null) ShowUpdate(); else await Check(true); };
        timer.Tick += async (_, _) => { if (DateTimeOffset.UtcNow >= nextCheck) await Check(false); };
        timer.Start();
        // Run only after the WinForms message loop/synchronization context exists.
        EventHandler? start = null;
        start = async (_, _) => { Application.Idle -= start; await Check(false); };
        Application.Idle += start;
    }

    async Task Check(bool manual)
    {
        if (busy || installing) return;
        busy = true;
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            var release = await client.Check(timeout.Token);
            // A new tray session gets one notification regardless of a previous snooze.
            // Keep this pending across network failures during Windows startup.
            bool notifyOnStartup = startupCheckPending;
            startupCheckPending = false;
            nextCheck = DateTimeOffset.UtcNow.AddHours(3);
            if (UpdateClient.ParseVersion(release.Version) <= UpdateClient.ParseVersion(current))
            {
                latest = null;
                if (manual) MessageBox.Show($"Bạn đang dùng Signing Gateway {current}. Chưa có phiên bản mới.", "Cập nhật");
                return;
            }
            if (latest?.Version != release.Version) notifyAfter = DateTimeOffset.MinValue;
            latest = release;
            if (manual) { ShowUpdate(); return; }
            Deferred? deferred = null;
            try { deferred = JsonSerializer.Deserialize<Deferred>(File.ReadAllText(Path.Combine(stateDir, "deferred.json"))); }
            catch { /* Missing/corrupt preferences must not interrupt the gateway. */ }
            if (!notifyOnStartup && deferred?.Version == release.Version && deferred.Until > DateTimeOffset.UtcNow) return;
            if (DateTimeOffset.UtcNow < notifyAfter) return;
            notifyAfter = DateTimeOffset.UtcNow.AddHours(24);
            icon.ShowBalloonTip(10000, $"Có phiên bản {release.Version}", "Signing Gateway có bản cập nhật mới. Bấm để tải cập nhật hoặc chọn Để sau.", ToolTipIcon.Info);
            ShowUpdate();
        }
        catch (Exception e)
        {
            nextCheck = DateTimeOffset.UtcNow.AddMinutes(30);
            if (manual) MessageBox.Show("Không kiểm tra được bản cập nhật.\n" + e.Message, "Signing Gateway", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        finally { busy = false; }
    }

    void Defer(Release release)
    {
        notifyAfter = DateTimeOffset.UtcNow.AddHours(24);
        try
        {
            Directory.CreateDirectory(stateDir);
            File.WriteAllText(Path.Combine(stateDir, "deferred.json"), JsonSerializer.Serialize(new Deferred(release.Version, notifyAfter)));
        }
        catch { /* Keep the in-memory snooze even if preferences cannot be written. */ }
    }

    void ShowUpdate()
    {
        if (latest == null || installing) return;
        if (dialog != null) { dialog.Activate(); return; }
        var release = latest;
        var form = new Form { Text = "Cập nhật Signing Gateway", ClientSize = new Size(480, 265),
            StartPosition = FormStartPosition.CenterScreen, FormBorderStyle = FormBorderStyle.FixedDialog,
            MaximizeBox = false, MinimizeBox = false, AutoScaleMode = AutoScaleMode.Dpi };
        dialog = form;
        var title = new Label { Text = $"Có phiên bản {release.Version}", Left = 20, Top = 20, Width = 440, Height = 32, Font = new Font(SystemFonts.MessageBoxFont!.FontFamily, 16, FontStyle.Bold) };
        var notes = new Label { Text = $"Phiên bản hiện tại: {current}\n\n{release.ReleaseNotes ?? "Bản cập nhật Signing Gateway mới."}", Left = 20, Top = 65, Width = 440, Height = 85, AutoEllipsis = true };
        var status = new Label { Left = 20, Top = 158, Width = 440, Height = 36 };
        var download = new Button { Text = "Tải cập nhật", Left = 190, Top = 212, Width = 130, Height = 32 };
        var later = new Button { Text = "Để sau", Left = 330, Top = 212, Width = 130, Height = 32 };
        bool accepted = false;
        bool working = false;
        later.Click += (_, _) => form.Close();
        form.FormClosing += (_, e) => { if (working) { e.Cancel = true; return; } if (!accepted) Defer(release); };
        form.FormClosed += (_, _) => { dialog = null; form.Dispose(); };
        download.Click += async (_, _) =>
        {
            if (working) return;
            working = installing = true;
            download.Enabled = later.Enabled = false;
            string? file = null;
            try
            {
                status.Text = "Đang tải bản cập nhật…";
                using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(15));
                file = await client.Download(release, stateDir, new Progress<int>(p => status.Text = $"Đang tải bản cập nhật: {p}%"), timeout.Token);
                status.Text = "Đang mở bộ cài. Vui lòng chấp nhận yêu cầu quyền Windows.";
                // The elevated installer confirms stopping the gateway and preserves configuration.
                using var setup = Process.Start(new ProcessStartInfo(file) { UseShellExecute = true, Arguments = "/UPDATE=1 /SILENT /NORESTART" })
                    ?? throw new IOException("Không mở được bộ cài.");
                status.Text = "Đang cập nhật…";
                await setup.WaitForExitAsync();
                if (setup.ExitCode != 0) throw new IOException($"Bộ cài chưa hoàn tất (mã {setup.ExitCode}). Phiên bản hiện tại chưa được xác nhận cập nhật.");
                // Normally setup closes this tray and starts the new one during file replacement.
                status.Text = "Bộ cài đã hoàn tất. Khởi động lại ứng dụng thông báo để đọc phiên bản mới.";
                accepted = true;
            }
            catch (Win32Exception e) when (e.NativeErrorCode == 1223) { status.Text = "Đã hủy yêu cầu quyền Windows. Chưa cập nhật."; }
            catch (Exception e) { status.Text = "Chưa cập nhật. Bạn có thể thử lại."; MessageBox.Show(form, e.Message, "Không cập nhật được", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
            finally
            {
                working = installing = false;
                download.Enabled = later.Enabled = true;
                if (file != null) { try { File.Delete(file); } catch { } }
            }
        };
        form.Controls.AddRange(new Control[] { title, notes, status, download, later });
        form.CancelButton = later;
        form.Show();
    }

    protected override void ExitThreadCore()
    {
        timer.Stop(); timer.Dispose(); icon.Visible = false; icon.Dispose(); http.Dispose();
        base.ExitThreadCore();
    }
}
