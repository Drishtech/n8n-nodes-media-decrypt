# n8n-nodes-media-decrypt

An n8n community node for decrypting WhatsApp media files with comprehensive error handling and proper MAC verification.

![n8n-nodes-media-decrypt](https://img.shields.io/badge/n8n-community%20node-blue)
![Version](https://img.shields.io/badge/version-0.1.3-green)

## Installation

To install this node in your n8n instance:

```bash
npm install n8n-nodes-media-decrypt
```

## Features

- ✅ **Decrypt WhatsApp media files** (images, videos, audio, documents)
- ✅ **Proper MAC verification** with multiple fallback methods
- ✅ **Smart MIME type selection** based on message type
- ✅ **WhatsApp icon display** in n8n interface (fixed in v0.1.3)
- ✅ **Comprehensive error handling** with detailed debugging information
- ✅ **Input validation** and retry logic for downloads
- ✅ **Support for large files** (up to 100MB)

## Usage

1. **URL**: The direct download URL of the encrypted WhatsApp media file (usually ends with `.enc`)
2. **Media Key**: The base64-encoded media key from the WhatsApp message metadata
3. **Message Type**: Select the appropriate message type:
   - **Audio Message** - for voice messages and audio files
   - **Image Message** - for photos and images  
   - **Video Message** - for videos and GIFs
   - **Document Message** - for documents and other files
4. **MIME Type**: The expected MIME type of the decrypted file (automatically filtered based on message type)

## Supported MIME Types

The MIME Type dropdown is now **context-aware** and only shows relevant options based on the selected Message Type:

### Audio Message Types
- OGG (WhatsApp Voice Messages) - **Default**
- MP3, MP4/M4A, WAV, AAC

### Image Message Types  
- JPEG - **Default**
- PNG, WebP, GIF

### Video Message Types
- MP4 - **Default**
- WebM, AVI, MOV

### Document Message Types
- PDF - **Default**
- Word (.docx), Excel (.xlsx), PowerPoint (.pptx)
- ZIP, RAR archives
- Plain text, Binary/Unknown files

## What's Fixed in v0.1.3

### 🔧 **MAC Verification Algorithm**
- **Complete rewrite** of the WhatsApp media decryption algorithm
- **Proper HKDF implementation** with correct key derivation order
- **Multiple MAC verification methods** to handle different WhatsApp versions
- **Detailed error messages** with debugging information for troubleshooting

### 🎨 **Icon Display Issue**
- **Fixed icon path** in build process
- **SVG icon properly copied** to dist folder during build
- **WhatsApp icon now displays correctly** in n8n interface

### 🎯 **Smart MIME Type Dropdown**
- **Context-aware MIME type selection** - dropdown only shows relevant formats
- **Automatic filtering** based on message type selection
- **Better organization** with grouped format categories

### 🛡️ **Enhanced Input Validation**
- **Comprehensive parameter validation** with detailed error messages
- **Base64 media key validation** to catch encoding issues early
- **URL and file size validation** to prevent common errors

### 🔄 **Improved Download Handling**
- **Retry logic** for failed downloads (up to 3 attempts)
- **Increased timeout** for large files (60 seconds)
- **Support for files up to 100MB**
- **Better error reporting** for download failures

## Troubleshooting

### MAC Verification Failed Error
If you encounter MAC verification errors, the new version provides detailed debugging information:

1. **Check the media key**: Ensure it's valid base64 and complete
2. **Verify message type**: Must match the actual WhatsApp message type
3. **Check the URL**: Ensure it points to the actual encrypted file
4. **File integrity**: The download might be corrupted or incomplete

The error message now includes:
- File sizes and key lengths
- Message type and encryption parameters
- Specific suggestions for resolution

### Icon Not Showing (Fixed in v0.1.3)
- ✅ **Icon is now properly included** in the package
- ✅ **Build process fixed** to copy SVG files
- If you still don't see the icon, restart your n8n instance

### Installation Issues
If you encounter installation issues:
```bash
# Clear npm cache
npm cache clean --force

# Reinstall the node
npm uninstall n8n-nodes-media-decrypt
npm install n8n-nodes-media-decrypt@latest
```

## Version History

### v0.1.3 (Latest) 🎉
- ✅ **Complete rewrite** of WhatsApp media decryption algorithm
- ✅ **Fixed MAC verification** with proper HKDF implementation
- ✅ **Fixed icon display** issue in n8n
- ✅ **Smart MIME type dropdown** with context-aware filtering
- ✅ **Enhanced error handling** with detailed debugging information
- ✅ **Improved download reliability** with retry logic
- ✅ **Better input validation** and comprehensive parameter checking
- ✅ **Support for large files** (up to 100MB)

### v0.1.2
- ✅ Enhanced MIME type dropdown with better organization
- ✅ Smart default MIME type selection based on message type
- ✅ Improved error messages and validation
- ✅ Added User-Agent header for better compatibility

### v0.1.1
- Initial release with basic decryption functionality

## Technical Details

### Encryption Algorithm
This node implements the correct WhatsApp media decryption algorithm:

1. **HKDF Key Derivation**: Derives IV, cipher key, and MAC key from the media key
2. **MAC Verification**: Verifies HMAC-SHA256 with multiple fallback methods
3. **AES-256-CBC Decryption**: Decrypts the media content
4. **Input Validation**: Comprehensive validation of all parameters

### Security
- Media keys are never logged or stored
- URLs are truncated in output for security
- Proper error handling prevents information leakage

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

If you encounter issues:
1. Check the troubleshooting section above
2. Verify your inputs (media key, message type, URL)
3. Look at the detailed error messages for specific guidance
4. Open an issue with the debug information if needed 