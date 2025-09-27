# Local Development Setup

## Prerequisites
- Python 3.11 or higher
- Oracle Database

## Database Configuration

### Option 1: Use Environment Variable (Recommended)
Set the DATABASE_URL environment variable to point to your database:

```bash
export DATABASE_URL="oracle+oracledb://username:password@host:port/service_name"
```

### Option 2: Use Default Oracle Database
The application is configured to use Oracle database by default:

```bash
export DATABASE_URL="oracle+oracledb://oracleuser:oracle@ec2-52-202-108-33.compute-1.amazonaws.com:1521/orcl"
```

### Option 3: Create Local Oracle Database
Create a local Oracle database or service as needed for your environment.

## Running the Application

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set environment variables:
```bash
export DATABASE_URL="your_oracle_database_connection_string"
export SESSION_SECRET="your_secret_key"
```

3. Run the application:
```bash
python main.py
```

The application will:
- Try to load database configuration from the SystemConfig table
- Fall back to the DATABASE_URL environment variable
- Create all necessary database tables automatically

## Troubleshooting

### Database Connection Errors
- Ensure Oracle Database is running
- Verify database connection string is correct
- Check if the service/database exists
- Verify username/password credentials

### Missing Tables
The application automatically creates all required tables when started. If tables are missing, the application will recreate them.

### Configuration Issues
The system supports dynamic database configuration via the web interface. Once the application is running, you can configure database settings through the web UI under "Configurações → Banco de Dados".