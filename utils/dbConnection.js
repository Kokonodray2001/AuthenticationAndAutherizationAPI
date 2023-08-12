const mongoose =  require('mongoose');
const connect = mongoose.connect("mongodb+srv://Kokonod:koko1koko2@cluster0.hhzzx0i.mongodb.net/?retryWrites=true&w=majority",{useNewUrlParser :  true},mongoose.set('strictQuery',true)).then(()=>console.log("connected mongo")).catch(err=>console.log(err))
module.exports = connect;