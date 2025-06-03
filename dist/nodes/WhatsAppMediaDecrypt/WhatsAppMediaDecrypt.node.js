"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.WhatsAppMediaDecrypt = void 0;
const n8n_workflow_1 = require("n8n-workflow");
const axios_1 = __importDefault(require("axios"));
const crypto = __importStar(require("crypto"));
// Proper HKDF implementation for WhatsApp media decryption
function hkdf(ikm, salt, info, length) {
    // Extract phase: PRK = HMAC-Hash(salt, IKM)
    const prk = crypto.createHmac('sha256', salt).update(ikm).digest();
    // Expand phase
    const n = Math.ceil(length / 32);
    let okm = Buffer.alloc(0);
    let t = Buffer.alloc(0);
    for (let i = 1; i <= n; i++) {
        const hmac = crypto.createHmac('sha256', prk);
        hmac.update(t);
        hmac.update(info);
        hmac.update(Buffer.from([i]));
        t = hmac.digest();
        okm = Buffer.concat([okm, t]);
    }
    return okm.slice(0, length);
}
function decryptWhatsAppMedia(encryptedData, mediaKey, messageType) {
    const mediaKeyBuffer = Buffer.from(mediaKey, 'base64');
    // WhatsApp uses specific info strings for different media types
    const mediaInfo = {
        'imageMessage': 'WhatsApp Image Keys',
        'videoMessage': 'WhatsApp Video Keys',
        'audioMessage': 'WhatsApp Audio Keys',
        'documentMessage': 'WhatsApp Document Keys'
    };
    const info = mediaInfo[messageType];
    if (!info) {
        throw new Error(`Unsupported message type: ${messageType}. Supported types: ${Object.keys(mediaInfo).join(', ')}`);
    }
    // Use empty salt as per WhatsApp implementation
    const salt = Buffer.alloc(32, 0);
    // Derive keys using HKDF: IV (16) + cipher key (32) + MAC key (32) + refKey (32) = 112 bytes
    const derivedKeys = hkdf(mediaKeyBuffer, salt, Buffer.from(info, 'utf8'), 112);
    const iv = derivedKeys.slice(0, 16);
    const cipherKey = derivedKeys.slice(16, 48);
    const macKey = derivedKeys.slice(48, 80);
    // Note: bytes 80-112 are refKey, not used in current implementation
    // WhatsApp format: [encrypted_data][mac] where mac is last 10 bytes
    if (encryptedData.length < 10) {
        throw new Error('Encrypted data too small to contain MAC (minimum 10 bytes required)');
    }
    const mac = encryptedData.slice(-10);
    const encrypted = encryptedData.slice(0, -10);
    // Verify MAC: HMAC-SHA256(macKey, iv + encrypted) truncated to 10 bytes
    const dataToAuthenticate = Buffer.concat([iv, encrypted]);
    const computedMac = crypto.createHmac('sha256', macKey)
        .update(dataToAuthenticate)
        .digest()
        .slice(0, 10);
    if (!mac.equals(computedMac)) {
        // Try alternative MAC calculation (encrypted data only, without IV)
        const altComputedMac = crypto.createHmac('sha256', macKey)
            .update(encrypted)
            .digest()
            .slice(0, 10);
        if (!mac.equals(altComputedMac)) {
            // Debug information for troubleshooting
            const debugInfo = {
                encryptedLength: encryptedData.length,
                macLength: mac.length,
                ivLength: iv.length,
                cipherKeyLength: cipherKey.length,
                macKeyLength: macKey.length,
                mediaKeyLength: mediaKeyBuffer.length,
                messageType: messageType,
                info: info
            };
            throw new Error(`MAC verification failed. This could indicate:
1. Incorrect media key (verify base64 encoding)
2. Wrong message type selected
3. Corrupted or incomplete download
4. File is not a WhatsApp encrypted media file

Debug info: ${JSON.stringify(debugInfo, null, 2)}`);
        }
    }
    // Decrypt using AES-256-CBC
    try {
        const decipher = crypto.createDecipheriv('aes-256-cbc', cipherKey, iv);
        decipher.setAutoPadding(true);
        const decrypted = Buffer.concat([
            decipher.update(encrypted),
            decipher.final()
        ]);
        // Validate decrypted data is not empty
        if (decrypted.length === 0) {
            throw new Error('Decryption resulted in empty data');
        }
        return decrypted;
    }
    catch (error) {
        throw new Error(`AES decryption failed: ${error instanceof Error ? error.message : 'Unknown encryption error'}`);
    }
}
function getFileNameFromType(messageType, mimetype) {
    // Extract extension from MIME type, with fallbacks
    let extension = 'bin';
    if (mimetype.includes('/')) {
        const mimeTypeMap = {
            'audio/ogg': 'ogg',
            'audio/mpeg': 'mp3',
            'audio/mp4': 'm4a',
            'audio/wav': 'wav',
            'audio/aac': 'aac',
            'image/jpeg': 'jpg',
            'image/png': 'png',
            'image/webp': 'webp',
            'image/gif': 'gif',
            'video/mp4': 'mp4',
            'video/webm': 'webm',
            'video/avi': 'avi',
            'video/quicktime': 'mov',
            'application/pdf': 'pdf',
            'text/plain': 'txt',
            'application/zip': 'zip'
        };
        extension = mimeTypeMap[mimetype] || mimetype.split('/')[1] || 'bin';
    }
    const typeMap = {
        'audioMessage': 'whatsapp_audio',
        'imageMessage': 'whatsapp_image',
        'videoMessage': 'whatsapp_video',
        'documentMessage': 'whatsapp_document'
    };
    const prefix = typeMap[messageType] || 'whatsapp_file';
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    return `${prefix}_${timestamp}.${extension}`;
}
class WhatsAppMediaDecrypt {
    constructor() {
        this.description = {
            displayName: 'WhatsApp Media Decrypt',
            name: 'whatsAppMediaDecrypt',
            icon: 'file:whatsapp.svg',
            group: ['transform'],
            version: 1,
            description: 'Decrypt WhatsApp media files using mediaKey with proper MAC verification',
            defaults: {
                name: 'WhatsApp Media Decrypt',
            },
            inputs: ['main'],
            outputs: ['main'],
            properties: [
                {
                    displayName: 'URL',
                    name: 'url',
                    type: 'string',
                    default: '',
                    required: true,
                    description: 'URL of the encrypted WhatsApp media file (usually ends with .enc)',
                    placeholder: 'https://example.com/encrypted-media.enc'
                },
                {
                    displayName: 'Media Key',
                    name: 'mediaKey',
                    type: 'string',
                    default: '',
                    required: true,
                    description: 'Base64-encoded media key for decryption (obtained from WhatsApp message metadata)',
                    placeholder: 'ABC123...XYZ789='
                },
                {
                    displayName: 'Message Type',
                    name: 'messageType',
                    type: 'options',
                    options: [
                        {
                            name: 'Audio Message',
                            value: 'audioMessage',
                            description: 'For voice messages and audio files'
                        },
                        {
                            name: 'Image Message',
                            value: 'imageMessage',
                            description: 'For photos and images'
                        },
                        {
                            name: 'Video Message',
                            value: 'videoMessage',
                            description: 'For videos and GIFs'
                        },
                        {
                            name: 'Document Message',
                            value: 'documentMessage',
                            description: 'For documents and other files'
                        },
                    ],
                    default: 'imageMessage',
                    required: true,
                    description: 'Type of WhatsApp message - must match the actual media type',
                },
                {
                    displayName: 'MIME Type',
                    name: 'mimetype',
                    type: 'options',
                    options: [
                        // Audio formats
                        {
                            name: 'Audio - OGG (WhatsApp Voice Messages)',
                            value: 'audio/ogg',
                        },
                        {
                            name: 'Audio - MP3',
                            value: 'audio/mpeg',
                        },
                        {
                            name: 'Audio - MP4/M4A',
                            value: 'audio/mp4',
                        },
                        {
                            name: 'Audio - WAV',
                            value: 'audio/wav',
                        },
                        {
                            name: 'Audio - AAC',
                            value: 'audio/aac',
                        },
                    ],
                    displayOptions: {
                        show: {
                            messageType: ['audioMessage'],
                        },
                    },
                    default: 'audio/ogg',
                    required: true,
                    description: 'Expected MIME type of the decrypted audio file',
                },
                {
                    displayName: 'MIME Type',
                    name: 'mimetype',
                    type: 'options',
                    options: [
                        // Image formats
                        {
                            name: 'Image - JPEG',
                            value: 'image/jpeg',
                        },
                        {
                            name: 'Image - PNG',
                            value: 'image/png',
                        },
                        {
                            name: 'Image - WebP',
                            value: 'image/webp',
                        },
                        {
                            name: 'Image - GIF',
                            value: 'image/gif',
                        },
                    ],
                    displayOptions: {
                        show: {
                            messageType: ['imageMessage'],
                        },
                    },
                    default: 'image/jpeg',
                    required: true,
                    description: 'Expected MIME type of the decrypted image file',
                },
                {
                    displayName: 'MIME Type',
                    name: 'mimetype',
                    type: 'options',
                    options: [
                        // Video formats
                        {
                            name: 'Video - MP4',
                            value: 'video/mp4',
                        },
                        {
                            name: 'Video - WebM',
                            value: 'video/webm',
                        },
                        {
                            name: 'Video - AVI',
                            value: 'video/avi',
                        },
                        {
                            name: 'Video - MOV',
                            value: 'video/quicktime',
                        },
                    ],
                    displayOptions: {
                        show: {
                            messageType: ['videoMessage'],
                        },
                    },
                    default: 'video/mp4',
                    required: true,
                    description: 'Expected MIME type of the decrypted video file',
                },
                {
                    displayName: 'MIME Type',
                    name: 'mimetype',
                    type: 'options',
                    options: [
                        // Document formats
                        {
                            name: 'Document - PDF',
                            value: 'application/pdf',
                        },
                        {
                            name: 'Document - Text',
                            value: 'text/plain',
                        },
                        {
                            name: 'Document - Word (.docx)',
                            value: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                        },
                        {
                            name: 'Document - Excel (.xlsx)',
                            value: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                        },
                        {
                            name: 'Document - PowerPoint (.pptx)',
                            value: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
                        },
                        {
                            name: 'Archive - ZIP',
                            value: 'application/zip',
                        },
                        {
                            name: 'Archive - RAR',
                            value: 'application/x-rar-compressed',
                        },
                        {
                            name: 'Other - Binary/Unknown',
                            value: 'application/octet-stream',
                        },
                    ],
                    displayOptions: {
                        show: {
                            messageType: ['documentMessage'],
                        },
                    },
                    default: 'application/pdf',
                    required: true,
                    description: 'Expected MIME type of the decrypted document file',
                },
            ],
        };
    }
    async execute() {
        const items = this.getInputData();
        const returnData = [];
        for (let i = 0; i < items.length; i++) {
            try {
                const url = this.getNodeParameter('url', i);
                const mediaKey = this.getNodeParameter('mediaKey', i);
                const messageType = this.getNodeParameter('messageType', i);
                const mimetype = this.getNodeParameter('mimetype', i);
                // Comprehensive input validation
                if (!url || typeof url !== 'string' || url.trim().length === 0) {
                    throw new Error('URL is required and must be a non-empty string');
                }
                if (!mediaKey || typeof mediaKey !== 'string' || mediaKey.trim().length === 0) {
                    throw new Error('Media Key is required and must be a non-empty string');
                }
                // Validate base64 media key
                try {
                    Buffer.from(mediaKey, 'base64');
                }
                catch (error) {
                    throw new Error('Media Key must be valid base64 encoded string');
                }
                if (!messageType || !['audioMessage', 'imageMessage', 'videoMessage', 'documentMessage'].includes(messageType)) {
                    throw new Error('Invalid message type. Must be one of: audioMessage, imageMessage, videoMessage, documentMessage');
                }
                if (!mimetype || typeof mimetype !== 'string' || mimetype.trim().length === 0) {
                    throw new Error('MIME Type is required and must be a non-empty string');
                }
                // Download the encrypted file with retry logic
                let encryptedData;
                let attempt = 0;
                const maxRetries = 3;
                while (attempt < maxRetries) {
                    try {
                        const response = await axios_1.default.get(url, {
                            responseType: 'arraybuffer',
                            timeout: 60000,
                            headers: {
                                'User-Agent': 'WhatsApp/2.23.20 Mozilla/5.0'
                            },
                            maxContentLength: 100 * 1024 * 1024,
                            maxBodyLength: 100 * 1024 * 1024
                        });
                        encryptedData = Buffer.from(response.data);
                        break;
                    }
                    catch (downloadError) {
                        attempt++;
                        if (attempt >= maxRetries) {
                            throw new Error(`Failed to download file after ${maxRetries} attempts: ${downloadError instanceof Error ? downloadError.message : 'Unknown download error'}`);
                        }
                        // Wait before retry
                        await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
                    }
                }
                if (encryptedData.length === 0) {
                    throw new Error('Downloaded file is empty (0 bytes)');
                }
                if (encryptedData.length < 10) {
                    throw new Error(`Downloaded file is too small (${encryptedData.length} bytes). WhatsApp encrypted files must be at least 10 bytes`);
                }
                // Decrypt the WhatsApp media
                const decryptedData = decryptWhatsAppMedia(encryptedData, mediaKey, messageType);
                // Validate decrypted data
                if (decryptedData.length === 0) {
                    throw new Error('Decryption successful but resulted in empty file');
                }
                // Create binary data for n8n
                const fileName = getFileNameFromType(messageType, mimetype);
                returnData.push({
                    json: {
                        fileName,
                        fileSize: decryptedData.length,
                        originalEncryptedSize: encryptedData.length,
                        messageType,
                        mimetype,
                        url: url.substring(0, 100) + (url.length > 100 ? '...' : ''),
                        decryptionSuccess: true,
                        timestamp: new Date().toISOString()
                    },
                    binary: {
                        [fileName]: {
                            data: decryptedData.toString('base64'),
                            fileName,
                            mimeType: mimetype,
                        },
                    },
                });
            }
            catch (error) {
                const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred during decryption';
                if (this.continueOnFail()) {
                    returnData.push({
                        json: {
                            error: errorMessage,
                            decryptionSuccess: false,
                            messageType: this.getNodeParameter('messageType', i),
                            timestamp: new Date().toISOString(),
                            url: this.getNodeParameter('url', i)
                        },
                    });
                    continue;
                }
                throw new n8n_workflow_1.NodeOperationError(this.getNode(), error, {
                    itemIndex: i,
                });
            }
        }
        return [returnData];
    }
}
exports.WhatsAppMediaDecrypt = WhatsAppMediaDecrypt;
