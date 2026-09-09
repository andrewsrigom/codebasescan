import express from 'express';

const app = express();
app.post('/webhooks/:provider', async (_request, response) => response.sendStatus(204));
