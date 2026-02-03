require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const admin = require('./firebase'); 
const multer = require('multer');
const path = require('path');
const helmet = require('helmet'); 
const fs = require('fs');
const Razorpay = require('razorpay');

const app = express();
const PORT = process.env.PORT || 5000;

if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD) {
    console.error('❌ ERROR: Admin credentials not found in .env file!');
    process.exit(1);
}

console.log('✅ Admin credentials loaded from environment variables');
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/public', express.static('public'));

const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

// --- MONGODB CONNECTION ---
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('✅ MongoDB Connected'))
    .catch(err => console.error('❌ DB Error:', err));


//---Razorpay instance---
const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET
});

// --- SCHEMAS ---
const UserSchema = new mongoose.Schema({
    uid: { type: String, required: true, unique: true },
    phone: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String },
    name: { type: String, default: 'New User' },
    role: { type: String, enum: ['user', 'owner', 'admin'], default: 'user' },
    isBlocked: { type: Boolean, default: false },
    earnings: { type: Number, default: 0 },
    recentBooking: String,
    cart: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Hotel' }],
    documents: { aadhar: String, pan: String }
}, { timestamps: true });

const HotelSchema = new mongoose.Schema({
    name: { type: String, required: true },
    location: { type: String, required: true },
    city: { type: String, required: true },
    pincode: String,
    address: String,
    price: { type: Number, required: true },
    
    rating: { type: Number, default: 0 },
    stars: { type: Number, default: 3 },
    image: String,
    videoUrl: String,
    amenities: [String],
    description: String,
    type: { type: String, enum: ['Budget', 'Premium', 'Resort', 'Business'], default: 'Budget' },
    
    ownerId: String,
    ownerPhone: String,
    status: { type: String, enum: ['pending', 'approved', 'suspended'], default: 'pending' },
    
    isCoupleFriendly: { type: Boolean, default: false },
    payAtHotel: { type: Boolean, default: false },
    isPetFriendly: { type: Boolean, default: false },
    isFamilyFriendly: { type: Boolean, default: false },
    roomFacilities: [String],
    facilities: [String],
    roomType: String,
    
    policies: { 
        cancellation: String, 
        checkIn: String, 
        checkOut: String, 
        idReq: String 
    },

    businessDetails: {
        ownerName: String,
        aadhar: String,
        pan: String,
        gst: String,
        bankAccount: String,
        ifsc: String,
        accountHolderName: String,
        propertyTax: String,
        rentLease: String,
        hotelLicense: String,
        electricityBill: String,
        foodLicense: String,
        aadharPhoto: String,
        passbookPhoto: String
    },

    roomCount: Number,
    roomCategories: [{
        type: String,
        price: Number,
        size: String,
        maxOccupancy: Number,
        bedType: String
    }],

    photos: {
        hotel: [String],
        rooms: [String],
        exterior: [String],
        reception: String,
        room: [String],
        bathroom: String,
        restaurant: String,
        parking: String
    },

    agreements: {
        platformTerms: { type: Boolean, default: false },
        commission: { type: Boolean, default: false },
        dataUsage: { type: Boolean, default: false },
        cancellationRefund: { type: Boolean, default: false }
    },

    isAvailable: { type: Boolean, default: true }
}, { timestamps: true });

const BookingSchema = new mongoose.Schema({
    userId: String,
    hotelId: { type: mongoose.Schema.Types.ObjectId, ref: 'Hotel' },
    hotelName: String,
    hotelImage: String,
    date: String,
    checkInDate: String,
    checkOutDate: String,
    totalAmount: Number,
    status: { type: String, enum: ['Pending', 'Confirmed', 'Completed', 'Cancelled', 'Upcoming', 'Rejected'], default: 'Pending' },
    customerName: String,
    rooms: Number,
    paymentMode: String,
    addons: {
        breakfast: Boolean,
        extraBed: Boolean
    },
    ownerPhone: String,
    // ADD THESE NEW FIELDS:
    paymentStatus: { 
        type: String, 
        enum: ['pending', 'paid', 'failed', 'refunded'], 
        default: 'pending' 
    },
    razorpayOrderId: String,
    razorpayPaymentId: String,
    razorpaySignature: String,
    paymentDate: Date,
    refundId: String,
    refundAmount: Number
}, { timestamps: true });

const ReviewSchema = new mongoose.Schema({
    userId: String,
    userName: String,
    hotelId: { type: mongoose.Schema.Types.ObjectId, ref: 'Hotel' },
    rating: { type: Number, min: 1, max: 5 },
    cleanliness: { type: Number, min: 1, max: 5 },
    staff: { type: Number, min: 1, max: 5 },
    breakfast: { type: Number, min: 0, max: 5 },
    comment: String,
    photos: [String],
    date: String,
    ownerReply: String,
    isReported: { type: Boolean, default: false }
}, { timestamps: true });

const User = mongoose.model('User', UserSchema);
const Hotel = mongoose.model('Hotel', HotelSchema);
const Booking = mongoose.model('Booking', BookingSchema);
const Review = mongoose.model('Review', ReviewSchema);

// --- FILE UPLOAD CONFIG ---
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ 
    storage,
    limits: { fileSize: 10 * 1024 * 1024 },
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|pdf/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        if (extname && mimetype) cb(null, true);
        else cb(new Error('Only images and PDFs allowed'));
    }
});

// --- AUTH ROUTES ---
app.post('/api/auth/firebase-login', async (req, res) => {
    const { token, userData, type, targetRole } = req.body;
    
    try {
        const decodedToken = await admin.auth().verifyIdToken(token);
        const { uid, phone_number } = decodedToken;

        let user = await User.findOne({ uid });

        if (!user && userData?.email) user = await User.findOne({ email: userData.email });
        if (!user && (userData?.phone || phone_number)) user = await User.findOne({ phone: userData?.phone || phone_number });

        const finalPhone = userData.phone ? `+91${userData.phone.replace('+91', '')}` : phone_number;

        if (type === 'signup') {
            if (user) {
                user.uid = uid;
                user.name = userData.name;
                user.email = userData.email;
                user.password = userData.password;
                user.role = targetRole || userData.role || 'user';
                user.phone = finalPhone;
            } else {
                user = new User({
                    uid,
                    phone: finalPhone,
                    email: userData.email,
                    name: userData.name,
                    password: userData.password,
                    role: targetRole || userData.role || 'user'
                });
            }
            await user.save();
        } else {
            // LOGIN FLOW
            if (!user) return res.status(404).json({ error: 'Account not found. Please Sign Up.' });
            
            // Check if this is an admin login attempt using environment variables
            const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
            const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
            
            if (userData.email === ADMIN_EMAIL && userData.password === ADMIN_PASSWORD) {
                // Verify the credentials match
                if (user.email === ADMIN_EMAIL) {
                    // Update user role to admin if not already
                    if (user.role !== 'admin') {
                        user.role = 'admin';
                        user.name = 'Super Admin'; // Set admin name
                        await user.save();
                    }
                    // Allow login without additional password check for admin
                } else {
                    return res.status(401).json({ error: 'Invalid admin credentials' });
                }
            } else {
                // Regular user login - check password
                if (userData.password && user.password && user.password !== userData.password) {
                    return res.status(400).json({ error: 'Incorrect Password.' });
                }
            }
            
            if (user.uid !== uid) { 
                user.uid = uid; 
                await user.save(); 
            }
            
            if (targetRole === 'owner' && user.role === 'user') {
                user.role = 'owner';
                await user.save();
            }
        }

        if (user.isBlocked) return res.status(403).json({ error: 'Account Blocked' });

        res.json({ message: 'Success', user });
    } catch (error) {
        console.error('Auth Error:', error);
        if (error.code === 11000) return res.status(400).json({ error: 'Email/Phone already exists.' });
        res.status(401).json({ error: 'Verification Failed' });
    }
});


// --- USER PROFILE ROUTES ---
app.put('/api/users/update/:uid', async (req, res) => {
    try {
        const user = await User.findOneAndUpdate(
            { uid: req.params.uid },
            { $set: req.body },
            { new: true }
        );
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json(user);
    } catch (err) { 
        console.error('Update Error:', err);
        res.status(500).json({ error: err.message }); 
    }
});

app.get('/api/users/:uid', async (req, res) => {
    try {
        const user = await User.findOne({ uid: req.params.uid });
        if (!user) return res.status(404).json({ error: 'User not found' });
        res.json(user);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- HOTEL ROUTES ---
app.get('/api/hotels', async (req, res) => {
    try {
        const hotels = await Hotel.find({ status: 'approved', isAvailable: true });
        res.json(hotels);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/hotels/:id', async (req, res) => {
    try {
        const hotel = await Hotel.findById(req.params.id);
        if (!hotel) return res.status(404).json({ error: 'Hotel not found' });
        res.json(hotel);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/hotels/owner/:uid', async (req, res) => {
    try {
        const hotels = await Hotel.find({ ownerId: req.params.uid });
        res.json(hotels);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/hotels/add', upload.fields([
    { name: 'aadharPhoto', maxCount: 1 },
    { name: 'panPhoto', maxCount: 1 },
    { name: 'bankDoc', maxCount: 1 },
    { name: 'propertyTax', maxCount: 1 },
    { name: 'rentLease', maxCount: 1 },
    { name: 'hotelLicense', maxCount: 1 },
    { name: 'electricityBill', maxCount: 1 },
    { name: 'foodLicense', maxCount: 1 },
    { name: 'hotelPhotos', maxCount: 10 }
]), async (req, res) => {
    try {
        const hotelData = JSON.parse(req.body.data || '{}');
        
        if (req.files) {
            if (req.files.aadharPhoto) hotelData.businessDetails = { ...hotelData.businessDetails, aadharPhoto: `/uploads/${req.files.aadharPhoto[0].filename}` };
            if (req.files.panPhoto) hotelData.businessDetails = { ...hotelData.businessDetails, panPhoto: `/uploads/${req.files.panPhoto[0].filename}` };
            if (req.files.bankDoc) hotelData.businessDetails = { ...hotelData.businessDetails, bankDoc: `/uploads/${req.files.bankDoc[0].filename}` };
            if (req.files.hotelPhotos) {
                hotelData.image = `/uploads/${req.files.hotelPhotos[0].filename}`;
                hotelData.photos = {
                    hotel: req.files.hotelPhotos.map(f => `/uploads/${f.filename}`),
                    rooms: req.files.hotelPhotos.slice(3).map(f => `/uploads/${f.filename}`)
                };
            }
        }
        
        const owner = await User.findOne({ uid: hotelData.ownerId });
        if (owner) hotelData.ownerPhone = owner.phone;
        
        const newHotel = new Hotel(hotelData);
        await newHotel.save();
        
        await User.findOneAndUpdate({ uid: hotelData.ownerId }, { role: 'owner' });

        res.status(201).json(newHotel);
    } catch (err) { 
        console.error('Hotel Add Error:', err);
        res.status(500).json({ error: err.message }); 
    }
});

app.put('/api/hotels/:id', async (req, res) => {
    try {
        const hotel = await Hotel.findByIdAndUpdate(
            req.params.id,
            { $set: req.body },
            { new: true }
        );
        if (!hotel) return res.status(404).json({ error: 'Hotel not found' });
        res.json(hotel);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- BOOKING ROUTES ---
app.post('/api/bookings', async (req, res) => {
    try {
        const newBooking = new Booking(req.body);
        await newBooking.save();
        
        await User.findOneAndUpdate(
            { uid: req.body.userId }, 
            { recentBooking: req.body.hotelName }
        );
        
        const hotel = await Hotel.findById(req.body.hotelId);
        if (hotel && hotel.ownerId) {
            const commission = req.body.totalAmount * 0.15;
            const ownerEarning = req.body.totalAmount - commission;
            await User.findOneAndUpdate(
                { uid: hotel.ownerId }, 
                { $inc: { earnings: ownerEarning } }
            );
        }

        res.status(201).json(newBooking);
    } catch (err) { 
        console.error('Booking Error:', err);
        res.status(500).json({ error: err.message }); 
    }
});

app.get('/api/bookings/:uid', async (req, res) => {
    try {
        const bookings = await Booking.find({ userId: req.params.uid }).sort({ createdAt: -1 });
        res.json(bookings);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/bookings/hotel/:hotelId', async (req, res) => {
    try {
        const bookings = await Booking.find({ hotelId: req.params.hotelId }).sort({ createdAt: -1 });
        res.json(bookings);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/bookings/:id/status', async (req, res) => {
    try {
        const booking = await Booking.findByIdAndUpdate(
            req.params.id,
            { status: req.body.status },
            { new: true }
        );
        if (!booking) return res.status(404).json({ error: 'Booking not found' });
        res.json(booking);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- REVIEW ROUTES ---
app.post('/api/reviews', async (req, res) => {
    try {
        const newReview = new Review(req.body);
        await newReview.save();
        
        const reviews = await Review.find({ hotelId: req.body.hotelId, isReported: false });
        const avgRating = reviews.reduce((sum, r) => sum + r.rating, 0) / reviews.length;
        await Hotel.findByIdAndUpdate(req.body.hotelId, { rating: avgRating.toFixed(1) });
        
        res.status(201).json(newReview);
    } catch (err) { 
        console.error('Review Error:', err);
        res.status(500).json({ error: err.message }); 
    }
});

app.get('/api/reviews/hotel/:hotelId', async (req, res) => {
    try {
        const reviews = await Review.find({ hotelId: req.params.hotelId, isReported: false }).sort({ createdAt: -1 });
        res.json(reviews);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/reviews/:id/reply', async (req, res) => {
    try {
        const review = await Review.findByIdAndUpdate(
            req.params.id,
            { ownerReply: req.body.reply },
            { new: true }
        );
        if (!review) return res.status(404).json({ error: 'Review not found' });
        res.json(review);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/reviews/:id/report', async (req, res) => {
    try {
        const review = await Review.findByIdAndUpdate(
            req.params.id,
            { isReported: true },
            { new: true }
        );
        if (!review) return res.status(404).json({ error: 'Review not found' });
        res.json(review);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- ADMIN ROUTES ---
app.get('/api/admin/dashboard', async (req, res) => {
    try {
        const users = await User.find({});
        const hotels = await Hotel.find({});
        const pendingHotels = await Hotel.find({ status: 'pending' });
        const bookings = await Booking.find({});
        const reviews = await Review.find({});
        
        res.json({ 
            users, 
            hotels, 
            pendingHotels,
            bookings,
            reviews,
            stats: {
                totalUsers: users.length,
                totalHotels: hotels.length,
                totalBookings: bookings.length,
                pendingApprovals: pendingHotels.length
            }
        });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/admin/hotel/:id/status', async (req, res) => {
    try {
        const hotel = await Hotel.findByIdAndUpdate(
            req.params.id,
            { status: req.body.status },
            { new: true }
        );
        if (!hotel) return res.status(404).json({ error: 'Hotel not found' });
        res.json(hotel);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/admin/suspend-hotel/:id', async (req, res) => {
    try {
        const hotel = await Hotel.findById(req.params.id);
        if (!hotel) return res.status(404).json({ error: 'Hotel not found' });
        hotel.status = hotel.status === 'suspended' ? 'approved' : 'suspended';
        await hotel.save();
        res.json(hotel);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/api/admin/block-user/:id', async (req, res) => {
    try {
        const user = await User.findById(req.params.id);
        if (!user) return res.status(404).json({ error: 'User not found' });
        user.isBlocked = !user.isBlocked;
        await user.save();
        res.json(user);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/admin/users/search', async (req, res) => {
    try {
        const { q } = req.query;
        const users = await User.find({
            $or: [
                { name: { $regex: q, $options: 'i' } },
                { email: { $regex: q, $options: 'i' } },
                { phone: { $regex: q, $options: 'i' } },
                { uid: { $regex: q, $options: 'i' } }
            ]
        });
        res.json(users);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/admin/hotels/search', async (req, res) => {
    try {
        const { q } = req.query;
        const hotels = await Hotel.find({
            $or: [
                { name: { $regex: q, $options: 'i' } },
                { city: { $regex: q, $options: 'i' } },
                { location: { $regex: q, $options: 'i' } },
                { ownerId: { $regex: q, $options: 'i' } }
            ]
        });
        res.json(hotels);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/owner/earnings/:uid', async (req, res) => {
    try {
        const { range, startDate, endDate } = req.query;
        const hotels = await Hotel.find({ ownerId: req.params.uid });
        const hotelIds = hotels.map(h => h._id);
        
        let dateFilter = {};
        if (range === 'today') {
            const today = new Date();
            today.setHours(0, 0, 0, 0);
            dateFilter = { createdAt: { $gte: today } };
        } else if (range === 'week') {
            const weekAgo = new Date();
            weekAgo.setDate(weekAgo.getDate() - 7);
            dateFilter = { createdAt: { $gte: weekAgo } };
        } else if (range === 'month') {
            const monthAgo = new Date();
            monthAgo.setMonth(monthAgo.getMonth() - 1);
            dateFilter = { createdAt: { $gte: monthAgo } };
        } else if (startDate && endDate) {
            dateFilter = { 
                createdAt: { 
                    $gte: new Date(startDate), 
                    $lte: new Date(endDate) 
                } 
            };
        }
        
        const bookings = await Booking.find({
            hotelId: { $in: hotelIds },
            status: { $in: ['Confirmed', 'Completed'] },
            ...dateFilter
        });
        
        const totalRevenue = bookings.reduce((sum, b) => sum + b.totalAmount, 0);
        const commission = totalRevenue * 0.15;
        const netEarnings = totalRevenue - commission;
        
        res.json({
            totalRevenue,
            commission,
            netEarnings,
            bookingCount: bookings.length,
            bookings
        });
    } catch (err) { 
        console.error('Earnings Error:', err);
        res.status(500).json({ error: err.message }); 
    }
});

app.get('/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date() });
});


// Create Razorpay Order
app.post('/api/payment/create-order', async (req, res) => {
    try {
        const { amount, currency = 'INR', receipt } = req.body;
        
        const options = {
            amount: amount * 100, // Razorpay expects amount in paise
            currency,
            receipt: receipt || `receipt_${Date.now()}`,
            payment_capture: 1
        };
        
        const order = await razorpay.orders.create(options);
        console.log('✅ Razorpay order created:', order.id);
        
        res.json({
            success: true,
            orderId: order.id,
            amount: order.amount,
            currency: order.currency,
            key: process.env.RAZORPAY_KEY_ID
        });
    } catch (error) {
        console.error('❌ Razorpay order creation failed:', error);
        res.status(500).json({ 
            success: false, 
            error: error.message 
        });
    }
});

// Verify Razorpay Payment Signature
app.post('/api/payment/verify', async (req, res) => {
    try {
        const crypto = require('crypto');
        const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
        
        const sign = razorpay_order_id + '|' + razorpay_payment_id;
        const expectedSign = crypto
            .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
            .update(sign.toString())
            .digest('hex');
        
        if (razorpay_signature === expectedSign) {
            console.log('✅ Payment verified successfully');
            res.json({ 
                success: true, 
                message: 'Payment verified successfully',
                paymentId: razorpay_payment_id 
            });
        } else {
            console.log('❌ Payment verification failed');
            res.status(400).json({ 
                success: false, 
                message: 'Invalid signature' 
            });
        }
    } catch (error) {
        console.error('❌ Payment verification error:', error);
        res.status(500).json({ 
            success: false, 
            error: error.message 
        });
    }
});

// Get Payment Details
app.get('/api/payment/:paymentId', async (req, res) => {
    try {
        const payment = await razorpay.payments.fetch(req.params.paymentId);
        res.json({ success: true, payment });
    } catch (error) {
        console.error('❌ Fetch payment error:', error);
        res.status(500).json({ 
            success: false, 
            error: error.message 
        });
    }
});

// Refund Payment
app.post('/api/payment/refund', async (req, res) => {
    try {
        const { paymentId, amount } = req.body;
        
        const refund = await razorpay.payments.refund(paymentId, {
            amount: amount * 100, // Amount in paise
            speed: 'normal'
        });
        
        console.log('✅ Refund initiated:', refund.id);
        res.json({ 
            success: true, 
            refund,
            message: 'Refund initiated successfully' 
        });
    } catch (error) {
        console.error('❌ Refund error:', error);
        res.status(500).json({ 
            success: false, 
            error: error.message 
        });
    }
});

app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
