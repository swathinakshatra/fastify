const fastify = require('fastify')()
require('dotenv').config();
require('./helpers/db')();
require('./helpers/redis');
require('./helpers/validations');
fastify.register(require('./routes/admin'),{prefix:'api/admin'});
fastify.register(require('./routes/users'),{prefix:'api/users'});



const start = async () => {
  try {
    await fastify.listen({ port: 3000 })
    console.log("Listening on port 3000")
  } catch (err) {
    fastify.log.error(err)
    process.exit(1)
  }
}
start()