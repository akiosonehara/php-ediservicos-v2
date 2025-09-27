# Sistema de Transferência de Arquivos

## Overview
This Python-based Flask application is a comprehensive file transfer management system. It supports multiple protocols including FTP, SCP, HTTP, S3, Connect:Direct, and JASPPION. Key features include dual authentication (local and LDAP), advanced configuration, profile management, audit trails, and a responsive web interface. The system aims to provide robust control over enterprise file transfer services with a focus on security, compliance, and usability.

## User Preferences
Preferred communication style: Simple, everyday language.

## System Architecture

### UI/UX Decisions
The application uses Bootstrap 5 for a responsive design, Jinja2 for templating, Font Awesome for iconography, and custom jQuery for dynamic interactions. It features a sidebar navigation with a collapsible, mobile-friendly design. All protocol and functionality templates maintain consistent visualization patterns, including "Visualizar" and "Editar" buttons, and profile name links.

### Technical Implementations
The backend is built with Flask, utilizing SQLAlchemy ORM for database interactions. Oracle is the primary database, configured with connection pooling and health checks. Authentication is handled by Flask-Login, supporting both local users with secure password hashing and LDAP/Active Directory integration with group mapping and role-based access control. File handling employs Werkzeug for secure uploads, and Python's built-in logging system is used for debugging and auditing.

### Feature Specifications
- **Authentication System**: Dual authentication (local and LDAP/Active Directory) with role-based access control, secure session management, and activity tracking.
- **Profile Management**: CRUD operations for transfer profiles, with a protocol flag system to enable/disable specific transfer methods, and file upload capabilities for diagrams and documentation. Profiles are automatically pre-selected in dropdowns when creating related protocols/functionalities.
- **Protocol Support**: Comprehensive support for FTP, SCP, HTTP, S3, Connect:Direct, and JASPPION, each with dedicated configuration.
- **Audit and Monitoring**: A complete audit trail of all user actions, including data restoration capabilities with referential integrity validation, and a statistics dashboard.
- **Configuration Management**: Download functionality for source code, database dumps, and documentation.
- **Advanced Search**: Multi-table search capability across all `TB_` tables with content-based searching and detailed record views.

### System Design Choices
The system adopts a modular design with separate files for routes, models, forms, and utilities. Template inheritance ensures UI consistency. Data integrity is maintained through comprehensive referential integrity validation for all restore operations and TRIM functionality across all forms. Security considerations include CSRF protection, secure file upload validation, password hashing, and SQL injection prevention via ORM.

## External Dependencies

### Python Packages
- Flask
- Flask-SQLAlchemy
- Flask-Login
- Flask-WTF
- WTForms
- Werkzeug
- oracledb (Oracle adapter)
- python-ldap

### LDAP Integration Components
- `ldap_auth.py` module
- `LDAPAuthenticator` class

### Frontend Dependencies
- Bootstrap 5 (CDN)
- Font Awesome (CDN)
- jQuery

### File Storage
- Local file system for uploaded diagrams and documents (configurable directory, default 16MB limit, supports PDF, PNG, JPEG).