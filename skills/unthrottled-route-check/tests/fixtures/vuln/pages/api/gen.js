const { generateText } = require("ai");
module.exports = async (req, res) => res.json(await generateText({ model: "x", prompt: req.body }));
