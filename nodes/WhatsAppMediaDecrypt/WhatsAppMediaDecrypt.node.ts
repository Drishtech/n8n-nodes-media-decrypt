import { IExecuteFunctions } from 'n8n-core';
import {
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	NodeOperationError,
} from 'n8n-workflow';
import axios from 'axios';
import * as crypto from 'crypto';

// Proper HKDF implementation for WhatsApp
function hkdf(ikm: Buffer, salt: Buffer, info: Buffer, length: number): Buffer {
	// Extract phase
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

function decryptWhatsAppMedia(encryptedData: Buffer, mediaKey: string, messageType: string): Buffer {
	const mediaKeyBuffer = Buffer.from(mediaKey, 'base64');
	
	// WhatsApp uses different info strings for key derivation
	const mediaInfo = {
		'imageMessage': 'WhatsApp Image Keys',
		'videoMessage': 'WhatsApp Video Keys', 
		'audioMessage': 'WhatsApp Audio Keys',
		'documentMessage': 'WhatsApp Document Keys'
	};
	
	const info = mediaInfo[messageType as keyof typeof mediaInfo];
	if (!info) {
		throw new Error(`Unsupported message type: ${messageType}`);
	}
	
	// Derive keys: 32 bytes for IV + cipher key, 32 bytes for MAC key
	const mediaKeyExpanded = hkdf(mediaKeyBuffer, Buffer.alloc(32), Buffer.from(info, 'utf8'), 112);
	
	const iv = mediaKeyExpanded.slice(0, 16);
	const cipherKey = mediaKeyExpanded.slice(16, 48);
	const macKey = mediaKeyExpanded.slice(48, 80);
	
	// WhatsApp format: [encrypted_data][mac] where mac is last 10 bytes
	if (encryptedData.length < 10) {
		throw new Error('File too small to contain MAC');
	}
	
	const mac = encryptedData.slice(-10);
	const encrypted = encryptedData.slice(0, -10);
	
	// Verify HMAC-SHA256 truncated to 10 bytes
	const computedMac = crypto.createHmac('sha256', macKey)
		.update(iv)
		.update(encrypted)
		.digest()
		.slice(0, 10);
	
	if (!mac.equals(computedMac)) {
		throw new Error('MAC verification failed - invalid media key or corrupted data');
	}
	
	// Decrypt using AES-256-CBC
	const decipher = crypto.createDecipheriv('aes-256-cbc', cipherKey, iv);
	decipher.setAutoPadding(true);
	
	const decrypted = Buffer.concat([
		decipher.update(encrypted),
		decipher.final()
	]);
	
	return decrypted;
}

function getFileNameFromType(messageType: string, mimetype: string): string {
	const extension = mimetype.split('/')[1] || 'bin';
	const typeMap = {
		'audioMessage': 'audio',
		'imageMessage': 'image', 
		'videoMessage': 'video',
		'documentMessage': 'document'
	};
	
	const prefix = typeMap[messageType as keyof typeof typeMap] || 'file';
	return `${prefix}.${extension}`;
}

export class WhatsAppMediaDecrypt implements INodeType {
	description: INodeTypeDescription = {
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
				type: 'options',
				options: [
					// Audio formats
					{
						name: 'Audio - OGG',
						value: 'audio/ogg',
					},
					{
						name: 'Audio - MP3',
						value: 'audio/mpeg',
					},
					{
						name: 'Audio - MP4',
						value: 'audio/mp4',
					},
					{
						name: 'Audio - WAV',
						value: 'audio/wav',
					},
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
					// Video formats
					{
						name: 'Video - MP4',
						value: 'video/mp4',
					},
					{
						name: 'Video - WebM',
						value: 'video/webm',
					},
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
						name: 'Document - Word',
						value: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
					},
				],
				default: 'image/jpeg',
				required: true,
				description: 'Expected MIME type of the decrypted file',
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];

		for (let i = 0; i < items.length; i++) {
			try {
				const url = this.getNodeParameter('url', i) as string;
				const mediaKey = this.getNodeParameter('mediaKey', i) as string;
				const messageType = this.getNodeParameter('messageType', i) as string;
				const mimetype = this.getNodeParameter('mimetype', i) as string;

				// Download the encrypted file
				const response = await axios.get(url, { 
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
			} catch (error) {
				const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
				
				if (this.continueOnFail()) {
					returnData.push({
						json: {
							error: errorMessage,
							success: false,
							messageType: this.getNodeParameter('messageType', i) as string,
						},
					});
					continue;
				}
				throw new NodeOperationError(this.getNode(), error as Error, {
					itemIndex: i,
				});
			}
		}

		return [returnData];
	}
}