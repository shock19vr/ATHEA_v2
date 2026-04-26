import type { NextConfig } from 'next';

const BACKEND_URL = process.env.BACKEND_URL;

// Parse ALLOWED_DEV_ORIGINS from env if it exists
const allowedDevOrigins = process.env.ALLOWED_DEV_ORIGINS
  ? process.env.ALLOWED_DEV_ORIGINS.split(',').map(s => s.trim())
  : undefined;

const nextConfig: NextConfig = {
  ...(allowedDevOrigins && { allowedDevOrigins }),
  async rewrites() {
    return [
      {
        source: '/backend/:path*',
        destination: `${BACKEND_URL}/:path*`,
      },
    ];
  },
};

export default nextConfig;
