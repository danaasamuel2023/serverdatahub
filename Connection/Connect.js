const mongoose = require('mongoose');



const ConnectDB=()=>{
    const password = 'StudentMarket';
    const uri = `mongodb+srv://StudentMarket:${password}@cluster0.ukbatl8.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

    mongoose.connect(uri, {
        useNewUrlParser: true,
        useUnifiedTopology: true
      }).then(() => {
        console.log('Connected to MongoDB');
      }).catch(err => {
        console.error('Failed to connect to MongoDB', err);
      });
      
      

}

module.exports=ConnectDB;
