import os
import config

# Set Oracle Database URL using centralized config - força o uso do Oracle
os.environ['DATABASE_URL'] = config.ORACLE_DATABASE_URL

from app import app
import routes
import logging

if __name__ == "__main__":
    # Sequences to ensure they exist
    sequences = [
        'usuarios_id_seq',
        'tb_perfil_id_perfil_seq',
        'tb_ftp_id_ftp_seq',
        'tb_scp_id_scp_seq',
        'tb_http_id_http_seq',
        'tb_s3_id_s3_seq',
        'tb_mq_id_mq_seq',
        'tb_connect_direct_id_cd_seq',
        'tb_jasppion_id_jasppion_seq',
        'tb_cmd_id_cmd_seq',
        'tb_formato_id_formato_seq',
        'tb_header_trailer_id_header_trailer_seq',
        'tb_jcl_id_jcl_seq',
        'tb_mail_id_mail_seq',
        'tb_prm_id_prm_seq',
        'tb_ser_id_ser_seq',
        'tb_traducao_id_traducao_seq',
        'tb_ftpusers_id_ftpusers_seq',
        'tb_mailgroup_id_mailgroup_seq',
        'tb_roscoe_id_roscoe_seq',
        'audit_log_id_seq',
        'faq_id_seq',
        'system_config_id_seq'
    ]

    # Check and create sequences if they don't exist
    # This part is usually handled by migration scripts in a real application
    # For demonstration purposes, we'll assume they might need to be checked or created.
    # In a production environment, consider using a migration tool like Alembic.

    print(f"{config.APP_FULL_NAME} - Inicializando...")
    logging.info(f"{config.APP_FULL_NAME} - Inicializando...")
    
    # Configure port and debug mode based on environment
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("FLASK_ENV") != "production"
    
    app.run(host="0.0.0.0", port=port, debug=debug_mode)