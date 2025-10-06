# Use Node.js 18 Alpine for smaller image
FROM node:18-alpine

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy application code
COPY server.js ./

# Create logs directory
RUN mkdir -p logs

# Expose port (configurable via PORT env var, defaults to 8321)
EXPOSE 8321

# Start the application
CMD ["npm", "start"]