using Cascade.Core;

namespace Cascade.Win;
sealed class SecurityForm : Form
{
    readonly Workflow flow;
    readonly ComboBox target=new() { DropDownStyle=ComboBoxStyle.DropDownList,Width=400 };
    readonly TextBox report=new() { Multiline=true,ReadOnly=true,ScrollBars=ScrollBars.Both,WordWrap=false,Width=800,Height=240,BackColor=Theme.Panel,ForeColor=Theme.Text };
    readonly TextBox admin=Theme.Input("cascade-admin"), key=Theme.Input(), pass=Theme.Input("",true), ip=Theme.Input();
    readonly CheckBox firewall=Check("Включить firewall IPv4 / IPv6, сохранить SSH и VPN"), restrict=Check("VPN-порт второго VPS доступен только с первого"), fail2ban=Check("Защита SSH от перебора — Fail2ban"), updates=Check("Автообновления безопасности без автоматической перезагрузки"), noPassword=Check("Отключить SSH-вход по паролю"), noRoot=Check("Запретить прямой SSH-вход root");
    readonly NumericUpDown retry=Number(5,2,20), findtime=Number(10,1,1440), bantime=Number(60,1,10080);
    readonly FlowLayoutPanel content=new() { Dock=DockStyle.Fill,FlowDirection=FlowDirection.TopDown,WrapContents=false,AutoScroll=true,Padding=new Padding(24) };
    bool busy;
    int Index=>target.SelectedIndex;
    static CheckBox Check(string text)=>new() { Text=text,AutoSize=true,ForeColor=Theme.Text,Margin=new Padding(0,6,0,6) };
    static NumericUpDown Number(int value,int min,int max)=>new() { Value=value,Minimum=min,Maximum=max,Width=90 };
    static FlowLayoutPanel Row(params Control[] controls) { var p=new FlowLayoutPanel { AutoSize=true,WrapContents=true,Width=820 }; foreach(var c in controls)p.Controls.Add(c); return p; }
    void Note(string text)=>content.Controls.Add(new Label { Text=text,Width=805,AutoSize=true,MaximumSize=new Size(805,0),ForeColor=Theme.Muted,Margin=new Padding(0,6,0,10) });
    public SecurityForm(Workflow workflow)
    {
        flow=workflow; Text="Cascade · Безопасность серверов"; ClientSize=new Size(900,900); MinimumSize=new Size(850,650); StartPosition=FormStartPosition.CenterParent; BackColor=Theme.Background; ForeColor=Theme.Text; Font=Theme.Font(10); Controls.Add(content);
        content.Controls.Add(Theme.Label("Безопасность серверов",22,true)); target.Items.AddRange(["1 · Входной сервер","2 · Выходной сервер"]); target.SelectedIndex=0; content.Controls.Add(target);
        Button audit=Theme.Button("Проверить безопасность"), probe=Theme.Button("Активное зондирование"), pick=Theme.Button("Выбрать ключ…"), generate=Theme.Button("Создать ключ…"), create=Theme.Button("Создать администратора с ключом"), test=Theme.Button("Проверить существующий вход"), apply=Theme.Button("Применить выбранное…",true), restore=Theme.Button("Восстановить настройки…"), unban=Theme.Button("Снять бан SSH");
        content.Controls.Add(Row(audit,probe)); Note("Пробы проверяют TLS/HTTP без авторизации. REALITY использует целевой сайт. Отдельный HTTPS-фронтенд для Naive/AnyTLS здесь не устанавливается. Padding и обычный TLS сами по себе не скрывают VPN; проверка не гарантирует отсутствие блокировок.");
        content.Controls.Add(Theme.Label("SSH-ключ и отдельный администратор",14,true)); admin.PlaceholderText="Имя администратора"; admin.Width=400; content.Controls.Add(admin); key.Width=400; key.PlaceholderText="Приватный SSH-ключ"; content.Controls.Add(Row(key,pick,generate)); pass.Width=400; pass.PlaceholderText="Парольная фраза ключа, если задана"; content.Controls.Add(pass); content.Controls.Add(Row(create,test));
        Note("Неотмеченные пункты не изменяются. Новый администратор получает sudo без пароля для управления Cascade. Сохраните ключ и имя. Прежний вход сохраняется до отдельного запрета."); content.Controls.Add(noPassword); content.Controls.Add(noRoot);
        content.Controls.Add(firewall); content.Controls.Add(restrict); Note("Существующие правила сохраняются. SSH остаётся доступен на текущем порту. Firewall хостинга настраивается в панели хостинга.");
        content.Controls.Add(fail2ban); content.Controls.Add(Row(Theme.Label("Попыток",9),retry,Theme.Label("За минут",9),findtime,Theme.Label("Бан, минут",9),bantime)); content.Controls.Add(updates); content.Controls.Add(Row(apply,restore)); ip.Width=400; ip.PlaceholderText="IPv4 / IPv6 для разблокировки"; content.Controls.Add(Row(ip,unban));
        Note("После изменений проверяется новый SSH-сеанс и сквозной VPN-тест. Без подтверждения — автоматический откат через 240 секунд. Установленные пакеты и новый администратор сохраняются."); content.Controls.Add(report);
        report.Text="Выберите сервер и запустите аудит. Настройки меняются только по кнопке.";
        target.SelectedIndexChanged+=(_,_)=>{ restrict.Enabled=Index==1; report.Clear(); }; restrict.Enabled=false;
        audit.Click+=async(_,_)=>await Perform(async()=>report.Text=await flow.SecurityAudit(Index));
        probe.Click+=async(_,_)=>await Perform(async()=>report.Text=await flow.SecurityRun("probe",Index));
        pick.Click+=(_,_)=>{ using var d=new OpenFileDialog { Title="Приватный SSH-ключ Ed25519" }; if(d.ShowDialog(this)==DialogResult.OK)key.Text=d.FileName; };
        generate.Click+=(_,_)=>{
            using var d=new SaveFileDialog { Title="Сохранить приватный SSH-ключ",FileName="cascade-admin-ed25519",OverwritePrompt=true };
            if(d.ShowDialog(this)!=DialogResult.OK)return;
            try { SecurityKeys.Create(d.FileName); key.Text=d.FileName; pass.Clear(); report.Text="Ключ создан без парольной фразы; доступ к файлу ограничен владельцем. Сохраните резервную копию."; } catch(Exception e) { MessageBox.Show(this,e.Message); }
        };
        create.Click+=async(_,_)=>await Perform(()=>UseKey(true)); test.Click+=async(_,_)=>await Perform(()=>UseKey(false));
        apply.Click+=async(_,_)=>{
            if(!(firewall.Checked||fail2ban.Checked||updates.Checked||noPassword.Checked||noRoot.Checked))return;
            if((noPassword.Checked||noRoot.Checked)&&!flow.SecurityKeyVerified[Index]) { MessageBox.Show(this,"Сначала проверьте отдельного администратора по ключу."); return; }
            if(MessageBox.Show(this,$"Применить выбранные настройки на сервере {Index+1}? Будут установлены необходимые пакеты. Программа проверит SSH и каскад до отмены автоматического отката.","Безопасность",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)!=DialogResult.Yes)return;
            await Perform(async()=>report.Text=await flow.SecurityApply(Index,new() { ["firewall"]=firewall.Checked,["restrictExit"]=Index==1&&restrict.Checked,["fail2ban"]=fail2ban.Checked,["updates"]=updates.Checked,["noPassword"]=noPassword.Checked,["noRoot"]=noRoot.Checked,["retry"]=(int)retry.Value,["findtime"]=(int)findtime.Value*60,["bantime"]=(int)bantime.Value*60 }));
        };
        restore.Click+=async(_,_)=>{ if(MessageBox.Show(this,"Восстановить предыдущие SSH, firewall, Fail2ban и обновления? Более поздние изменения этих файлов также будут отменены.","Восстановление",MessageBoxButtons.YesNo,MessageBoxIcon.Warning)==DialogResult.Yes)await Perform(async()=>report.Text=await flow.SecurityRestore(Index)); };
        unban.Click+=async(_,_)=>await Perform(async()=>report.Text=await flow.SecurityRun("unban",Index,new() { ["ip"]=ip.Text.Trim() }));
        FormClosing+=(_,e)=>{ if(busy)e.Cancel=true; };
    }
    async Task UseKey(bool create) { await flow.SecurityUseKey(Index,admin.Text.Trim(),key.Text,pass.Text,create); report.Text="Вход администратора по ключу и sudo подтверждены. Доступы обновлены в памяти приложения. Для следующего запуска сохраните имя и приватный ключ."; }
    async Task Perform(Func<Task> action)
    {
        if(busy)return; busy=true; content.Enabled=false; Text="Cascade · Проверяем безопасность…";
        try { await action(); } catch(Exception e) { report.Text=flow.SafeError(e)+"\r\nПри потере связи после изменения настроек откат выполняется через 240 секунд. Запустите аудит. Установленные пакеты сохраняются."; }
        finally { busy=false; content.Enabled=true; restrict.Enabled=Index==1; Text="Cascade · Безопасность серверов"; }
    }
}
