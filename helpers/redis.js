const redis = require('redis');
const client = redis.createClient({
  host: process.env.REDIS_HOST,
  port: process.env.REDIS_PORT
});
client.connect()
client.on('connect', err => {
    console.log('Connected to redis..');
})

client.on('error', (err) => {
    console.log(err.message);
})
client.on('end', () => {
    console.log('Client disconnected to redis...');
});
module.exports = {
   redisSET: async(hash,data)=> {
    try {
      const result = await client.SET(hash,data);
      console.log(result);
      return result;
    } catch (error) {
      console.error(error);
      throw error;
    }
  },
   redisSETEX : async (key,expiryInSeconds,data) => {
    try {
     
      const result = await client.setEx(key,expiryInSeconds,data);
      console.log(result);
      return result;
    } catch (error) {
      console.error(error);
      throw error;
    }
  },
 
  redisexpire: async(hash,expired)=> {
    try {
      const result = await client.expire(hash,expired);
      console.log(result);
      return result;
    } catch (error) {
      console.error(error);
      throw error;
    }
  },
redisGET: async(key)=> {
    try {
      const result = await client.get(key);
      return result;
    } catch (error) {
      console.error(error);
      throw error;
    }
  },
  redisexpired: async(hash,expire)=> {
    try {
      const result = await client.expire(hash,expire);
      return result;
    } catch (error) {
      console.error(error);
      throw error;
    }
  },
  
  redishset: async (hash, key, data) => {
    var result = JSON.stringify(data);
    try {
      const reply = await client.hSet(hash, key, result);
      return reply;
    } catch (error) {
      console.error(error);
      throw error;
    }
  },
  redishexists: async (hash,key) => {
    const result = await client.hExists(hash,key);
    return result;
  },
  redishget: async (hash,key) => {
    const result = await client.hGet(hash,key);
    var reply = JSON.parse(result);
    return reply;
  },
  redisexists: async (key) => {
    const result = await client.exists(key);
    return result;
  },
  redisget: async (hash) => {
    const result = await client.get(hash);
    var reply = JSON.parse(result);
    return reply;
  },
 redisdelete:async (hash) => {
      try {
          const result = await client.del(hash);
          return result;
      } catch (error) {
          console.error(error);
          throw error;
      }
  },
  redishdelete: async (hash, key) => {
    try {
      const result = await client.HDEL(hash, key);
      return result;
    } catch (error) {
      console.error(error);
      throw error;
    }
  },
  redisupdate: async (hash,key,data) => {
    try {
      const result = await client.hSet(hash,key,data);
      if (!result) { 
        return null;
      }
      return JSON.parse(result);
    } catch (error) {
      console.error(error);
      throw error;
    }
  },

  findOneDocumentWithCache: async function (query, collectionName, key, expiryInSeconds) {
    try {
      if (!query || !collectionName || !key || typeof expiryInSeconds !== 'number') {
        throw new Error('Invalid input parameters');
      }
      const exists = await client.exists(key);
     if (exists) {
       const cachedData = await client.get(key);
        console.log("Data from Redis:", cachedData);
        return JSON.parse(cachedData);
      } else {
         const collection = eval(collectionName);
         const document = await collection.findOne(query);
       if (!document) {
          return null;
        } else {
         await client.setEx(key, expiryInSeconds, JSON.stringify(document));
          console.log("Data from MongoDB:", document);
          return document;
        }
      }
    } catch (error) {
      console.error(error);
      throw error;
    }
  },
};



