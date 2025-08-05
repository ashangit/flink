package org.apache.flink.core.security.watch;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.nio.file.WatchService;
import java.util.concurrent.ConcurrentHashMap;

import static java.nio.file.StandardWatchEventKinds.ENTRY_CREATE;
import static java.nio.file.StandardWatchEventKinds.ENTRY_DELETE;
import static java.nio.file.StandardWatchEventKinds.ENTRY_MODIFY;

public final class LocalFSWatchSingleton {
    // The field must be declared volatile so that double check lock would work
    // correctly.
    private static volatile LocalFSWatchSingleton instance;

    ConcurrentHashMap<WatchService, LocalFSWatchServiceListener> watchers = new ConcurrentHashMap<>();

    private LocalFSWatchSingleton() {
    }

    public static LocalFSWatchSingleton getInstance() {
        LocalFSWatchSingleton result = instance;
        if (result != null) {
            return result;
        }
        synchronized(LocalFSWatchSingleton.class) {
            if (instance == null) {
                instance = new LocalFSWatchSingleton();
            }
            return instance;
        }
    }

    public void registerPath(
            Path[] pathsToWatch,
            LocalFSWatchServiceListener callback) throws IOException {
        WatchService watcher = FileSystems.getDefault().newWatchService();
        for (Path pathToWatch : pathsToWatch) {
            Path realDirectoryPath = pathToWatch.toRealPath();
            realDirectoryPath.register(watcher, ENTRY_CREATE, ENTRY_DELETE, ENTRY_MODIFY);
        }
        callback.onWatchStarted(pathsToWatch[0]);
        watchers.put(watcher, callback);
    }
}
