export default {
  experimental: {
    serverActions: {
      allowedOrigins: ['*'],
    },
  },
  images: {
    remotePatterns: [{ protocol: 'http', hostname: '**' }],
  },
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          {
            key: 'Content-Security-Policy',
            value: "default-src 'self'; script-src 'self' 'unsafe-eval'",
          },
        ],
      },
    ];
  },
};
