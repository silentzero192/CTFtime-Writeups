#!/bin/bash

# Scallywag.net Ship-Mail Backup Script
# Version: 1.0
# Author: System Administrator
# Date: [Current Date, e.g., 25th Day of the 8th Moon, Year of Our Lord...]

# This script helps you create a local backup of your ship-mail mailbox.
# It will create a timestamped archive of your email data in your designated backup directory.

# --- Configuration ---
# IMPORTANT: Adjust these variables to match your system and preferences.

# 1. MAIL_DIR: The absolute path to your ship-mail directory.
#    This is where your email files (e.g., inbox, sent, drafts) are stored.
#    Example: /home/yourusername/.shipmail
MAIL_DIR="/home/$USER/.shipmail" 

# 2. BACKUP_ROOT_DIR: The directory where your backups will be stored.
#    This script will create a subdirectory within this path for each backup.
#    Example: /home/yourusername/ShipMail_Backups
BACKUP_ROOT_DIR="/home/$USER/ShipMail_Backups"

# 3. ARCHIVE_FORMAT: The compression format for your backup.
#    Options: "tar.gz" (compressed tar archive), "zip" (zip archive)
ARCHIVE_FORMAT="tar.gz" 

# --- Script Logic ---

echo "--- Scallywag.net Ship-Mail Backup Utility ---"

# Check if the mail directory exists
if [ ! -d "$MAIL_DIR" ]; then
    echo "Error: Mail directory not found at $MAIL_DIR."
    echo "Please ensure MAIL_DIR is correctly set in the script and that you have mail data."
    exit 1
fi

# Create backup root directory if it doesn't exist
if [ ! -d "$BACKUP_ROOT_DIR" ]; then
    echo "Creating backup directory: $BACKUP_ROOT_DIR"
    mkdir -p "$BACKUP_ROOT_DIR" || { echo "Error: Could not create backup directory."; exit 1; }
fi

# Generate a timestamp for the backup file
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE_NAME="shipmail_backup_${TIMESTAMP}.${ARCHIVE_FORMAT}"
FULL_BACKUP_PATH="${BACKUP_ROOT_DIR}/${BACKUP_FILE_NAME}"

echo "Preparing to backup mail from: $MAIL_DIR"
echo "Backup will be saved to: $FULL_BACKUP_PATH"

# Perform the backup based on the chosen archive format
case "$ARCHIVE_FORMAT" in
    "tar.gz")
        echo "Creating compressed tar archive..."
        tar -czf "$FULL_BACKUP_PATH" -C "$(dirname "$MAIL_DIR")" "$(basename "$MAIL_DIR")"
        ;;
    "zip")
        echo "Creating zip archive..."
        zip -r "$FULL_BACKUP_PATH" "$MAIL_DIR"
        ;;
    *)
        echo "Error: Unsupported ARCHIVE_FORMAT '$ARCHIVE_FORMAT'."
        echo "Please set ARCHIVE_FORMAT to 'tar.gz' or 'zip'."
        exit 1
        ;;
esac

# Check if the backup was successful
if [ $? -eq 0 ]; then
    echo "Backup successful! Your mailbox data has been saved."
    echo "Backup file size: $(du -h "$FULL_BACKUP_PATH" | cut -f1)"
else
    echo "Error: Backup failed. Please check for issues and try again."
    exit 1
fi

echo "--- Backup process complete ---"
```