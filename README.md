# YaraMan - YARA Rules Manager & File Scanner

YaraMan is a standalone web application for managing YARA rules and scanning files for malware detection. It provides an intuitive web interface with dedicated pages for file scanning and YARA rule management, featuring comprehensive threat detection results and advanced rule compilation support.

## Features

### YARA Rules Management
- **Upload Rules**: Support for individual `.yar`/`.yara` files and bulk `.zip` uploads
- **Advanced Rule Support**: Full support for YARA imports including `pe` module
- **Rule Validation**: Automatic syntax checking before upload
- **Rule Browser**: View all uploaded rules with metadata and rule counts
- **Rule Details**: Inspect rule content with syntax highlighting
- **Statistics Dashboard**: Track rule counts, file sizes, and recent uploads

### File Scanner (Main Page)
- **Multi-file Upload**: Scan multiple files simultaneously
- **Comprehensive Results**: Detailed threat detection with rule descriptions
- **Match Details**: Show matched strings, offsets, and content highlights
- **Rule Metadata**: Display rule author, description, and tags
- **File Analysis**: MD5 and SHA256 hash calculation with file size reporting
- **Visual Indicators**: Color-coded threat levels and status badges

### User Interface
- **Navbar Navigation**: Clean navigation between Scanner and YARA Rules pages
- **Responsive Design**: Modern Bootstrap-based interface that works on all devices
- **Dark/Light Mode**: Automatic theme switching with manual override options
- **Real-time Feedback**: Progress indicators and detailed status messages

### Security Features
- **Rule Validation**: YARA syntax validation prevents invalid rules
- **Module Support**: Safe handling of YARA imports with fallback error handling
- **Safe File Handling**: Temporary file processing with automatic cleanup
- **Secure Uploads**: Filename sanitization and file type validation

## Installation

### Prerequisites
- Python 3.8 or higher
- YARA library installed on your system

### Install YARA (Linux/macOS)
```bash
# Ubuntu/Debian
sudo apt-get install yara

# macOS with Homebrew
brew install yara

# Or build from source
git clone https://github.com/VirusTotal/yara.git
cd yara
./bootstrap.sh
./configure
make
sudo make install
```

### Install YaraMan
```bash
# Clone the repository
git clone <repository-url>
cd yaraman

# Install Python dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

## Usage

1. **Start the Application**
   ```bash
   python app.py
   ```
   The application will be available at `http://localhost:5002`

2. **Upload YARA Rules**
   - Navigate to the "YARA Rules" page from the navbar
   - Click "Upload Rules" to add new rule files
   - Support for individual `.yar`/`.yara` files or `.zip` archives
   - Rules with imports (like `import "pe"`) are fully supported

3. **Scan Files**
   - Use the main "Scanner" page (default homepage)
   - Select files to scan using the file picker
   - Click "Scan Files" to analyze against your uploaded rules
   - View comprehensive results with:
     - Rule descriptions and metadata
     - Matched string identifiers and content
     - File offsets and match lengths
     - Threat level indicators and tags

## API Endpoints

### YARA Rules Management
- `GET /api/yara/rules` - List all uploaded rules
- `GET /api/yara/rules/<filename>` - Get specific rule content
- `POST /api/yara/rules` - Upload new rule files
- `DELETE /api/yara/rules/<filename>` - Delete a rule file

### File Scanning
- `POST /api/scan` - Scan uploaded files against YARA rules
  - Returns detailed match information including:
    - Rule metadata (author, description, tags)
    - Matched strings with identifiers
    - File offsets and content snippets
    - File hashes (MD5, SHA256)

## Configuration

The application can be configured by modifying the following variables in `app.py`:

```python
app.config['YARA_RULES_FOLDER'] = 'yara_rules'  # Directory for YARA rules
app.config['UPLOAD_FOLDER'] = 'uploads'         # Temporary file uploads
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size
```

## Directory Structure

```
yaraman/
├── app.py                 # Main Flask application
├── index.html            # Frontend interface
├── requirements.txt      # Python dependencies
├── assets/              # Static assets (CSS, JS)
│   ├── styles.css
│   ├── color-modes.js
│   ├── main.js
│   └── ui.js
├── yara_rules/          # YARA rules storage (created automatically)
└── uploads/             # Temporary file uploads (created automatically)
```

## Security Considerations

- **File Size Limits**: Maximum upload size is limited to 100MB
- **File Type Validation**: Only allowed file types are processed
- **Temporary Storage**: Uploaded files are automatically deleted after scanning
- **Rule Validation**: All YARA rules are syntax-checked before storage
- **Secure Filenames**: Uploaded filenames are sanitized to prevent path traversal

## Dependencies

- **Flask**: Web framework for the backend API
- **yara-python**: Python bindings for YARA rule engine with full module support
- **Werkzeug**: WSGI utilities and secure filename handling
- **Bootstrap 5**: Modern responsive frontend framework
- **Font Awesome**: Professional icon set for enhanced UI

## Development

To run in development mode:

```bash
export FLASK_ENV=development
python app.py
```

The application will auto-reload on code changes and provide detailed error messages.

## Enhanced Scan Results

YaraMan provides comprehensive scan results that go beyond simple rule matching:

### Detailed Threat Information
- **Visual Threat Indicators**: Color-coded cards with red borders for threats, green for clean files
- **Rule Descriptions**: Shows the purpose and author of each matching rule
- **Threat Classification**: Displays rule tags (e.g., "executable", "basic_pe") as badges
- **Status Badges**: Clear "THREAT DETECTED" or "CLEAN" indicators

### String Match Analysis
- **Matched Identifiers**: Shows which specific strings triggered the rule (e.g., `$mz`, `$pe_header`)
- **Content Snippets**: Displays the actual matched content with highlighting
- **File Offsets**: Precise location in the file where matches were found
- **Match Statistics**: Number of instances for each string pattern

### File Analysis
- **Cryptographic Hashes**: MD5 and SHA256 fingerprints for file identification
- **File Size**: Human-readable file size information
- **Match Summary**: Total number of rules that detected the file

### Example Output
When scanning a PE executable, you might see results like:
- **Rule**: `BasicPEFile` by YaraMan - "Basic PE file detection"
- **Matched Strings**: 
  - `$dos_header`: "MZ" at offset 0
  - `$pe_header`: "PE" at offset 256
- **Tags**: executable, basic_pe
- **Status**: THREAT DETECTED

This level of detail helps security analysts understand exactly what patterns were detected and make informed decisions about file threats.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is released under the MIT License. See LICENSE file for details.

## Acknowledgments

- Built with Flask and Bootstrap for a modern web experience
- Powered by the YARA rule engine for malware detection
- UI components inspired by modern cybersecurity tools