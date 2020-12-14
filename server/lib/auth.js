const passport = require('passport');
const localStrategy = require('passport-local').Strategy;
const UserModel = require('../models/UserModel');

passport.use(
  new localStrategy(
    {
      usernameField: 'email',
    },
    async (username, password, done) => {
      try {
        const user = await UserModel.findOne({ email: username }).exec();
        if (!user) {
          return done(null, false, { message: 'invalid username or password' });
        }

        const passwordOk = await user.comparePassword(password);
        if (!passwordOk) {
          return done(null, false, { message: 'invalid username or password' });
        }

        return done(null, user);
      } catch (error) {
        done(error);
      }
    }
  )
);

passport.serializeUser((user, done) => done(null, user._id));

passport.deserializeUser(async (id, done) => {
  try {
    const user = await UserModel.findById(id).exec();
    done(null, user);
  } catch (error) {
    return done(error);
  }
});

module.exports = {
  initialize: passport.initialize(),
  session: passport.session(),
  setUser: (req, res, next) => {
    res.locals.user = req.user;
    return next();
  },
};
