DROP TABLE IF EXISTS aegis_execution_report_fences;

ALTER TABLE aegis_incident_reports
    DROP COLUMN IF EXISTS notification_requested;
