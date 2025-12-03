// init-mongo.js - MongoDB Initialization

db = db.getSiblingDB('nids_db');

db.createUser({
  user: 'nids_user',
  pwd: 'nids_password_change_me',
  roles: [
    {
      role: 'readWrite',
      db: 'nids_db'
    }
  ]
});

// Create collections
db.createCollection('alerts');
db.createCollection('traffic_logs');
db.createCollection('threat_statistics');

// Create indexes for performance
db.alerts.createIndex({ timestamp: -1 });
db.alerts.createIndex({ severity: 1 });
db.alerts.createIndex({ alert_type: 1 });
db.alerts.createIndex({ source_ip: 1 });

db.traffic_logs.createIndex({ timestamp: -1 });
db.traffic_logs.createIndex({ protocol: 1 });

print('MongoDB initialization completed successfully');
