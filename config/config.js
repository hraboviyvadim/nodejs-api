module.exports = {
  server: {
    port: process.env.PORT || 3000
  },
  db: {
    uri: process.env.MONGODB_URI || 'mongodb://admin:admin@ds125774.mlab.com:25774/test_db',
    options: {
      promiseLibrary: Promise,
      useMongoClient: true,
    }
  },
  jwt_secret: 'mysecretkey'
};