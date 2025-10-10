-- Migration script: Convert existing database from bcrypt to SRP authentication
-- This script migrates the users table from password_hash to srp_salt and srp_verifier

-- Check if old schema exists (password_hash column)
DO $$ 
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'users' AND column_name = 'password_hash'
    ) THEN
        -- Add new SRP columns if they don't exist
        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns 
            WHERE table_name = 'users' AND column_name = 'srp_salt'
        ) THEN
            ALTER TABLE users ADD COLUMN srp_salt VARCHAR(255);
        END IF;

        IF NOT EXISTS (
            SELECT 1 FROM information_schema.columns 
            WHERE table_name = 'users' AND column_name = 'srp_verifier'
        ) THEN
            ALTER TABLE users ADD COLUMN srp_verifier TEXT;
        END IF;

        -- Set placeholder values for existing users
        -- The backend will regenerate these on first startup
        UPDATE users 
        SET srp_salt = '$placeholder$', 
            srp_verifier = '$placeholder$'
        WHERE srp_salt IS NULL OR srp_verifier IS NULL;

        -- Make the new columns NOT NULL
        ALTER TABLE users ALTER COLUMN srp_salt SET NOT NULL;
        ALTER TABLE users ALTER COLUMN srp_verifier SET NOT NULL;

        -- Drop the old password_hash column
        ALTER TABLE users DROP COLUMN password_hash;

        RAISE NOTICE 'Migration complete: password_hash replaced with srp_salt and srp_verifier';
    ELSE
        RAISE NOTICE 'Migration not needed: database already using SRP schema';
    END IF;
END $$;
