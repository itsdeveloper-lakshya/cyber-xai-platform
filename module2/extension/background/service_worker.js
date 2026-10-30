/**
 * Background Service Worker (Section 6.6)
 * Enqueues scored metadata into persistent storage (chrome.storage.local).
 * Dispatches events to backend API using device token auth.
 * Retries on wake-up and chrome.alarms (lossless delivery).
 */

const API_BASE = "http://localhost:8000/api/v1";
const ALARM_NAME = "cyber-sentinel-sync";

// Setup recurring sync alarm every 1 minute
chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create(ALARM_NAME, { periodInMinutes: 1 });
  console.log("[Service Worker] Installed and sync alarm registered.");
});

// Alarm wake-up handler
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === ALARM_NAME) {
    flushEventQueue();
  }
});

// Message listener from content scripts & popup
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "QUEUE_EVENT") {
    enqueueEvent(msg.event);
    sendResponse({ status: "queued" });
  } else if (msg.type === "GET_STATUS") {
    getStatus().then(sendResponse);
    return true; // async response
  } else if (msg.type === "REGISTER_DEVICE") {
    registerDevice(msg.enrollmentCode, msg.userId).then(sendResponse);
    return true;
  }
});

async function enqueueEvent(eventPayload) {
  const store = await chrome.storage.local.get({ eventQueue: [], deviceId: null, user_id: "DEMO_USER" });
  eventPayload.device_id = store.deviceId;
  eventPayload.user_id = store.user_id;

  const queue = store.eventQueue || [];
  queue.push(eventPayload);
  await chrome.storage.local.set({ eventQueue: queue });
  console.log(`[Service Worker] Event ${eventPayload.event_id} stored in queue. Queue size: ${queue.length}`);

  // Attempt immediate flush
  flushEventQueue();
}

async function flushEventQueue() {
  const store = await chrome.storage.local.get({ eventQueue: [], deviceToken: null });
  const queue = store.eventQueue || [];
  if (queue.length === 0) return;

  const token = store.deviceToken;
  if (!token) {
    console.warn("[Service Worker] No device token registered. Events remain queued.");
    return;
  }

  const remainingQueue = [];
  for (const event of queue) {
    try {
      const resp = await fetch(`${API_BASE}/events`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`
        },
        body: JSON.stringify(event)
      });

      if (resp.status === 202 || resp.status === 201 || resp.status === 200) {
        console.log(`[Service Worker] Successfully sent event ${event.event_id}`);
      } else {
        console.warn(`[Service Worker] Server returned ${resp.status} for event ${event.event_id}. Retrying later.`);
        remainingQueue.push(event);
      }
    } catch (err) {
      console.warn(`[Service Worker] Network error sending event:`, err.message);
      remainingQueue.push(event);
    }
  }

  await chrome.storage.local.set({ eventQueue: remainingQueue, lastSync: new Date().toISOString() });
}

async function registerDevice(enrollmentCode, userId) {
  try {
    const resp = await fetch(`${API_BASE}/devices/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enrollment_code: enrollmentCode, user_id: userId })
    });
    const data = await resp.json();
    if (resp.ok && data.token) {
      await chrome.storage.local.set({
        deviceId: data.device_id,
        deviceToken: data.token,
        user_id: userId,
        rulesetVersion: data.ruleset_version || 1,
        modelVersion: data.model_version || 1
      });
      return { success: true, deviceId: data.device_id };
    }
    return { success: false, error: data.error || "Registration failed" };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

async function getStatus() {
  const store = await chrome.storage.local.get({
    deviceId: null,
    user_id: null,
    eventQueue: [],
    rulesetVersion: 1,
    modelVersion: 1,
    lastSync: "Never"
  });
  return {
    isRegistered: !!store.deviceId,
    deviceId: store.deviceId,
    userId: store.user_id,
    pendingEvents: (store.eventQueue || []).length,
    rulesetVersion: store.rulesetVersion,
    modelVersion: store.modelVersion,
    lastSync: store.lastSync
  };
}
