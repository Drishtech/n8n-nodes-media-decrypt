# n8n-nodes-media-decrypt

This is an n8n community node for decrypting WhatsApp media files. It allows you to decrypt WhatsApp media files (.enc) using the mediaKey and get the original media file in binary format.

This node is based on the [baileys-decode-enc-by-url](https://github.com/sostenesapollo/baileys-decode-enc-by-url) project by Sostenes Apollo, adapted to work as an n8n node.

## Installation

Follow the [installation guide](https://docs.n8n.io/integrations/community-nodes/installation/) in the n8n community nodes documentation.

## Usage

This node accepts the following parameters:

- **URL**: The direct URL to the encrypted WhatsApp media file (.enc)
- **Media Key**: The decryption key specific to the media file
- **Message Type**: The type of WhatsApp message (audio, image, video, or document)
- **MIME Type**: The expected MIME type of the decrypted file (e.g., audio/ogg, image/jpeg)

### Example Workflow

1. Webhook (receives WhatsApp message with URL and mediaKey)
2. WhatsApp Media Decrypt (this node)
3. OpenAI (for transcription or analysis)
4. Function (process the result)
5. Respond (send response back to user)

### Output

The node returns a binary item that can be used by other nodes:

```json
{
  "binary": {
    "data": {
      "data": "<base64_file_data>",
      "fileName": "audio.ogg",
      "mimeType": "audio/ogg"
    }
  }
}
```

## Credits

- Original decryption logic: [baileys-decode-enc-by-url](https://github.com/sostenesapollo/baileys-decode-enc-by-url) by Sostenes Apollo
- n8n node implementation: Federico

## License

[MIT](LICENSE.md) 