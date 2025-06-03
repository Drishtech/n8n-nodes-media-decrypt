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
// HKDF implementation for WhatsApp key derivation
function hkdf(ikm, salt, info, length) {
    const prk = crypto.createHmac('sha256', salt).update(ikm).digest();
    const infoWithCounter = Buffer.concat([info, Buffer.from([0x01])]);
    const okm = crypto.createHmac('sha256', prk).update(infoWithCounter).digest();
    return okm.slice(0, length);
}
function decryptWhatsAppMedia(encryptedData, mediaKey, messageType) {
    const mediaKeyBuffer = Buffer.from(mediaKey, 'base64');
    // WhatsApp-specific info strings for different media types
    const mediaInfo = {
        'imageMessage': 'WhatsApp Image Keys',
        'videoMessage': 'WhatsApp Video Keys',
        'audioMessage': 'WhatsApp Audio Keys',
        'documentMessage': 'WhatsApp Document Keys'
    };
    const info = mediaInfo[messageType];
    if (!info) {
        throw new Error(`Unsupported message type: ${messageType}`);
    }
    // Derive keys using HKDF
    const expanded = hkdf(mediaKeyBuffer, Buffer.alloc(32), Buffer.from(info), 112);
    const iv = expanded.slice(0, 16);
    const cipherKey = expanded.slice(16, 48);
    const macKey = expanded.slice(48, 80);
    // The last 10 bytes are MAC, rest is encrypted data
    const mac = encryptedData.slice(-10);
    const encrypted = encryptedData.slice(0, -10);
    // Verify MAC
    const computedMac = crypto.createHmac('sha256', macKey)
        .update(iv)
        .update(encrypted)
        .digest()
        .slice(0, 10);
    if (!mac.equals(computedMac)) {
        throw new Error('MAC verification failed - invalid media key or corrupted data');
    }
    // Decrypt the data
    const decipher = crypto.createDecipheriv('aes-256-cbc', cipherKey, iv);
    const decrypted = Buffer.concat([
        decipher.update(encrypted),
        decipher.final()
    ]);
    return decrypted;
}
function getFileNameFromType(messageType, mimetype) {
    const extension = mimetype.split('/')[1] || 'bin';
    const typeMap = {
        'audioMessage': 'audio',
        'imageMessage': 'image',
        'videoMessage': 'video',
        'documentMessage': 'document'
    };
    const prefix = typeMap[messageType] || 'file';
    return `${prefix}.${extension}`;
}
class WhatsAppMediaDecrypt {
    constructor() {
        this.description = {
            displayName: 'WhatsApp Media Decrypt',
            name: 'whatsAppMediaDecrypt',
            icon: 'file:whatsapp.svg',
            group: ['transform'],
            version: 1,
            description: 'Decrypt WhatsApp media files using mediaKey',
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
                    description: 'URL of the encrypted WhatsApp media file (.enc)',
                },
                {
                    displayName: 'Media Key',
                    name: 'mediaKey',
                    type: 'string',
                    default: '',
                    required: true,
                    description: 'Base64-encoded media key for decryption',
                },
                {
                    displayName: 'Message Type',
                    name: 'messageType',
                    type: 'options',
                    options: [
                        {
                            name: 'Audio Message',
                            value: 'audioMessage',
                        },
                        {
                            name: 'Image Message',
                            value: 'imageMessage',
                        },
                        {
                            name: 'Video Message',
                            value: 'videoMessage',
                        },
                        {
                            name: 'Document Message',
                            value: 'documentMessage',
                        },
                    ],
                    default: 'imageMessage',
                    required: true,
                    description: 'Type of the WhatsApp message',
                },
                {
                    displayName: 'MIME Type',
                    name: 'mimetype',
                    type: 'string',
                    default: 'image/jpeg',
                    required: true,
                    description: 'Expected MIME type of the decrypted file (e.g., audio/ogg, image/jpeg, video/mp4)',
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
                // Download the encrypted file
                const response = await axios_1.default.get(url, {
                    responseType: 'arraybuffer',
                    timeout: 30000
                });
                const encryptedData = Buffer.from(response.data);
                // Decrypt the WhatsApp media
                const decryptedData = decryptWhatsAppMedia(encryptedData, mediaKey, messageType);
                // Create binary data for n8n
                const fileName = getFileNameFromType(messageType, mimetype);
                returnData.push({
                    json: {
                        fileName,
                        fileSize: decryptedData.length,
                        messageType,
                        mimetype,
                        success: true
                    },
                    binary: {
                        data: {
                            data: decryptedData.toString('base64'),
                            fileName,
                            mimeType: mimetype,
                        },
                    },
                });
            }
            catch (error) {
                const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
                if (this.continueOnFail()) {
                    returnData.push({
                        json: {
                            error: errorMessage,
                            success: false,
                            messageType: this.getNodeParameter('messageType', i),
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
