import { IExecuteFunctions } from 'n8n-core';
import {
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	NodeOperationError,
} from 'n8n-workflow';
import axios from 'axios';
import * as crypto from 'crypto';

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
				description: 'URL of the encrypted WhatsApp media file',
			},
			{
				displayName: 'Media Key',
				name: 'mediaKey',
				type: 'string',
				default: '',
				required: true,
				description: 'Media key for decryption',
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
				default: 'audioMessage',
				required: true,
				description: 'Type of the WhatsApp message',
			},
			{
				displayName: 'MIME Type',
				name: 'mimetype',
				type: 'string',
				default: '',
				required: true,
				description: 'Expected MIME type of the decrypted file (e.g., audio/ogg, image/jpeg)',
			},
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];
		const self = this as unknown as WhatsAppMediaDecrypt;

		for (let i = 0; i < items.length; i++) {
			try {
				const url = this.getNodeParameter('url', i) as string;
				const mediaKey = this.getNodeParameter('mediaKey', i) as string;
				const messageType = this.getNodeParameter('messageType', i) as string;
				const mimetype = this.getNodeParameter('mimetype', i) as string;

				// Download the encrypted file
				const response = await axios.get(url, { responseType: 'arraybuffer' });
				const encryptedData = Buffer.from(response.data);

				// Decrypt the data using the mediaKey
				const decryptedData = await self.decryptMediaData(encryptedData, mediaKey, messageType);

				// Create binary data
				const binaryData = {
					data: decryptedData.toString('base64'),
					fileName: self.getFileNameFromType(messageType, mimetype),
					mimeType: mimetype,
				};

				returnData.push({
					json: {},
					binary: {
						data: binaryData,
					},
				});
			} catch (error) {
				if (this.continueOnFail()) {
					returnData.push({
						json: {
							error: (error as Error).message,
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

	private async decryptMediaData(
		encryptedData: Buffer,
		mediaKey: string,
		messageType: string,
	): Promise<Buffer> {
		// Convert mediaKey from base64 to buffer
		const mediaKeyBuffer = Buffer.from(mediaKey, 'base64');

		// Generate decryption key using HKDF
		const info = this.getMessageTypeInfo(messageType);
		const key = crypto.createHmac('sha256', mediaKeyBuffer)
			.update(info)
			.digest();

		// Decrypt the data using AES-256-CBC
		const decipher = crypto.createDecipheriv('aes-256-cbc', key, Buffer.alloc(16));
		const decrypted = Buffer.concat([
			decipher.update(encryptedData),
			decipher.final(),
		]);

		return decrypted;
	}

	private getMessageTypeInfo(messageType: string): string {
		switch (messageType) {
			case 'audioMessage':
				return 'WhatsApp Audio Keys';
			case 'imageMessage':
				return 'WhatsApp Image Keys';
			case 'videoMessage':
				return 'WhatsApp Video Keys';
			case 'documentMessage':
				return 'WhatsApp Document Keys';
			default:
				throw new Error(`Unsupported message type: ${messageType}`);
		}
	}

	private getFileNameFromType(messageType: string, mimetype: string): string {
		const extension = mimetype.split('/')[1];
		switch (messageType) {
			case 'audioMessage':
				return `audio.${extension}`;
			case 'imageMessage':
				return `image.${extension}`;
			case 'videoMessage':
				return `video.${extension}`;
			case 'documentMessage':
				return `document.${extension}`;
			default:
				return `file.${extension}`;
		}
	}
} 