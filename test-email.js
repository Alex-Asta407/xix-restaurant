const nodemailer = require('nodemailer');
require('dotenv').config();

async function testEmail() {
  console.log('Testing email configuration...');
  
  // Use the same credentials as your working Python code
  const user = 'akonstantinov582@gmail.com';
  const pass = 'zssp ebxm ajbe hngi';
  
  console.log('SMTP_USER:', user);
  console.log('SMTP_PASS:', '***hidden***');

  const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,
    auth: {
      user: user,
      pass: pass,
    },
    tls: {
      rejectUnauthorized: false
    }
  });

  try {
    // Test connection
    await transporter.verify();
    console.log('✅ SMTP connection successful!');

    // Send test email
    const info = await transporter.sendMail({
      from: 'XIX Restaurant <akonstantinov582@gmail.com>',
      to: 'akonstantinov582@gmail.com', // Send to yourself
      subject: 'XIX Restaurant - Email Test',
      html: `
        <h2>Email Test Successful!</h2>
        <p>This is a test email from the XIX Restaurant system.</p>
        <p>If you receive this, the email configuration is working correctly.</p>
        <p>Time: ${new Date().toLocaleString()}</p>
      `
    });

    console.log('✅ Test email sent successfully!');
    console.log('Message ID:', info.messageId);
  } catch (error) {
    console.error('❌ Email test failed:');
    console.error(error.message);
    
    if (error.code === 'EAUTH') {
      console.log('\n💡 This looks like an authentication error.');
      console.log('Make sure you\'re using your Gmail App Password, not your regular password.');
      console.log('Get your App Password from: https://myaccount.google.com/apppasswords');
    }
  }
}

testEmail();
