// Private fork: the desktop auto-updater is permanently disabled for zero
// network egress. main.ts gates setupAutoUpdater() on this flag, so no
// update feed is configured and no startup update check ever runs.
export const UPDATES_ENABLED = false;
export const COST_TRACKING_ENABLED = true;
export const ANNOUNCEMENTS_ENABLED = false;
export const CONFIGURATION_ENABLED = true;
export const TELEMETRY_UI_ENABLED = true;
export const DICTATION_ALLOWED_PROVIDERS: string[] | null = null;

