package io.nekohasekai.sagernet.scanner

import android.content.Context
import android.util.Log
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit

/**
 * Weekly full rescan worker.
 *
 * Runs the full [HostileAppScanner.scanAll] (all 5 layers including
 * DEX) and refreshes the cache. Scheduled with battery-friendly
 * constraints so the expensive DEX scan never runs while the device
 * is on battery or in active use:
 *
 *   requiresCharging      = true
 *   requiresBatteryNotLow = true
 *   requiresDeviceIdle    = true  (API 23+)
 *   networkType           = NOT_REQUIRED
 *
 * Effective cost: one scan per week while plugged in and idle. Users
 * who never charge overnight may see less frequent runs — that's
 * acceptable because the [HostileAppScanReceiver] handles the per-
 * install delta in real time. The weekly rescan is only a safety net
 * for cache drift.
 */
class HostileAppScanWorker(
    appContext: Context,
    params: WorkerParameters,
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        return try {
            val scanner = HostileAppScanner(applicationContext)
            val results = scanner.scanAll()
            val cached = results.map {
                HostileAppScanCache.fromScanResult(applicationContext.packageManager, it)
            }
            HostileAppScanCache.putAll(applicationContext, cached)
            Log.i(TAG, "weekly rescan done, cached ${cached.size} entries")
            Result.success()
        } catch (e: Exception) {
            Log.w(TAG, "weekly rescan failed: ${e.message}")
            Result.retry()
        }
    }

    companion object {
        private const val TAG = "HostileAppScanWorker"
        private const val WORK_NAME = "hostile_app_weekly_rescan"

        fun schedule(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.NOT_REQUIRED)
                .setRequiresCharging(true)
                .setRequiresBatteryNotLow(true)
                .apply {
                    if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
                        setRequiresDeviceIdle(true)
                    }
                }
                .build()

            val request = PeriodicWorkRequestBuilder<HostileAppScanWorker>(7, TimeUnit.DAYS)
                .setConstraints(constraints)
                .build()

            WorkManager.getInstance(context)
                .enqueueUniquePeriodicWork(
                    WORK_NAME,
                    ExistingPeriodicWorkPolicy.KEEP,
                    request,
                )
        }

        fun cancel(context: Context) {
            WorkManager.getInstance(context).cancelUniqueWork(WORK_NAME)
        }
    }
}
