#!/bin/sh
echo "Waiting for MongoDB to be ready..."
until mongo --host mongodb:27017 --eval "db.adminCommand('ping')" > /dev/null 2>&1; do
  sleep 1
done

echo "Restoring base database..."
mongorestore --host mongodb:27017 -d gallery2 mongodbdata/gallery2

echo "Updating client credentials in MongoDB with environment variables..."
mongo --host mongodb:27017 gallery2 --eval "db.clients.updateOne({clientID: 'photoprint'}, {\$set: {clientID: '$CLIENT_ID', clientSecret: '$CLIENT_SECRET'}}, {upsert: true})"

echo "Database seeding completed successfully."
