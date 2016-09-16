mods =
  packets : require('../files/packets.iced')
  stream : require('../files/stream.iced')
  break_stuff : require('../files/break_stuff.iced')

v = Object.keys(mods)
v.sort()
for k in v
  console.log(k)

{BrowserRunner} = require('iced-test')

window.onload = () ->
  br = new BrowserRunner({log : 'log', rc : 'rc'})
  await br.run(mods, defer(rc))
