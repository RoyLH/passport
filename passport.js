// const passport = require('passport');

// console.log(passport);
/*

Authenticator { // node repl打印 默认会带构造函数名称 比如这里的 Authenticator
    _key: 'passport',
    _strategies: {
        session: SessionStrategy {
            name: 'session',
            _deserializeUser: [Function: bound]
        }
    },
    _serializers: [],
    _deserializers: [],
    _infoTransformers: [],
    _framework: {
        initialize: [Function: initialize],
        authenticate: [Function: authenticate]
    },
    _userProperty: 'user',
    _sm: SessionManager {
        _key: 'passport',
        _serializeUser: [Function: bound]
    },
    Authenticator: [Function: Authenticator],
    Passport: [Function: Authenticator],
    Strategy: {
        [Function: Strategy] Strategy: [Circular]
    },
    strategies: {
        SessionStrategy: {
            [Function: SessionStrategy] super_: [Object]
        }
    }
}

*/


// console.log(passport.__proto__ == passport.constructor.prototype); //ture

// console.log(passport.__proto__.constructor.prototype);
// console.log(passport.constructor.prototype);

/*
Authenticator {
  init: [Function],
  use: [Function],
  unuse: [Function],
  framework: [Function],
  initialize: [Function],
  authenticate: [Function],
  authorize: [Function],
  session: [Function],
  serializeUser: [Function],
  deserializeUser: [Function],
  transformAuthInfo: [Function],
  _strategy: [Function] 
};
*/

// 所以真正的passport为：
/*
{
    _key: 'passport',
    _strategies: {
        session: SessionStrategy {
            name: 'session',
            _deserializeUser: [Function: bound]
        }
    },
    _serializers: [],
    _deserializers: [],
    _infoTransformers: [],
    _framework: {
        initialize: [Function: initialize],
        authenticate: [Function: authenticate]
    },
    _userProperty: 'user',
    _sm: {
        _key: 'passport',
        _serializeUser: [Function: bound]
    },
    Authenticator: [Function: Authenticator],
    Passport: [Function: Authenticator],
    Strategy: {
        [Function: Strategy] Strategy: [Circular]
    },
    strategies: {
        SessionStrategy: {
            [Function: SessionStrategy] super_: [Object]
        }
    },
    init: [Function],
    use: [Function],
    unuse: [Function],
    framework: [Function],
    initialize: [Function],
    authenticate: [Function],
    authorize: [Function],
    session: [Function],
    serializeUser: [Function],
    deserializeUser: [Function],
    transformAuthInfo: [Function],
    _strategy: [Function] 
}
*/
// =====================================================================================================================
// 应用自动的初始化设置
// function Authenticator() {
//     this._key = 'passport';
//     this._strategies = {};
//     this._serializers = [];
//     this._deserializers = [];
//     this._infoTransformers = [];
//     this._framework = null;
//     this._userProperty = 'user';

//     this.init();
// }
// Authenticator.prototype.init = function () {
//     this.framework(require('./framework/connect')());
//     // 1. 将 http/request.js 中针对req的拓展方法（login/logIn logout/logOut, isAuthenticated, isUnauthenticated）
//     //    挂在 http.IncomingMessage.prototype上 从而实现了真正意义上的req拓展（这个过程详见 framework/connect.js）
//     // 2. 将middleware目录下封装的 authenticate中间件 和 initialize中间件
//     //    挂载到了this._framework的同名属性中(这个过程详见 framework/connect.js和 Authenticator.prototype.framework)

//     this.use(new SessionStrategy(this.deserializeUser.bind(this)));
//     // 1. this.deserializeUser.bind(this)在这里实际上返回的是 Authenticator.prototype.deserializeUser函数
//     //    至于.bind(this)是因为在new SessionStrategy()的参数位置会改变this指向 所以用.bind(this)手动复原this指向,
//     //    重点：只改变this指向 不执行函数（这也是bind 和 call/apply方法的区别)
//     // 2. new SessionStrategy(this.deserializeUser.bind(this))这个过程产生一个对象：
//     //    { name: 'session', _deserializeUser: [Function: bound] }(同时还有自于SessionStrategy.prototype的 authenticate方法)
//     //    上面这个[Function: bound] 就是this.deserializeUser.bind(this))函数
//     // 3. this.use(new SessionStrategy(this.deserializeUser.bind(this)))将2中产生的对象挂载在了this._strategies.session上

//     this._sm = new SessionManager({
//         key: this._key
//     }, this.serializeUser.bind(this));
//     // 1. this.serializeUser.bind(this)和this.deserializeUser.bind(this)同理 实际上返回的是 Authenticator.prototype.serializeUser函数
//     // 2. new SessionManager({ key: this._key }, this.serializeUser.bind(this));产生一个对象:
//     //    { _key: 'passport', _serializeUser: [Function: bound] } (同时还有自于SessionManager.prototype的 logIn 和 logOut 方法)
//     //    上面这个[Function: bound] 就是this.serializeUser.bind(this))函数
//     // 3. 将上述对象赋值给 this._sm 属性
// };

// =====================================================================================================================

// 由源码分析 在 passport模块调用放的Express应用中 关于login实际的执行过程是：
// 1 const passport = require('passport'); // 引入passport模块
// 2 app.use(passport.initialize()); // 启动passport模块 对passport进行初始化 否则后面的验证方法无法执行
// 3 app.use(passport.session()); // 用于Express应用追踪用户会话 这个主要是为了记住用户的登录状态 可以指定session的过期时间
// 4 passport.serializeUser((user, done) => done(null, user.id)); 在passport配置中注册序列化函数到this._serializers执行栈中(以便于后期再req.login时候用到)
// 5 passport.deserializeUser((id, done) => done(null, 利用user.id查询到的user)); 在passport配置中注册反序列化函数到this._deserializers执行栈中 便于后期取出user使用
// 6 登录login过程
//  => req.login(user, done); 
//  => http/request.js/req.login (在这个过程中将参数user正式挂载在了req.user上，通过req.user可以访问， 再去执行以下登陆过程 若是最终失败 设置req.user = null并且done(err))
//  => sessionmanager.js/SessionManager.prototype.logIn 
//  => authenticator.js/Authenticator.prototype.serializeUser
//  => 在Authenticator.prototype.serializeUser函数中进入到了passport.serializeUser((user, done) => done(null, user.id));注册在this._serializers中的函数
//  => 这个done(null, user.id)回调到sessionmanager.js/SessionManager.prototype.logIn 中处理剩余逻辑
//  => sessionmanager.js / SessionManager.prototype.logIn
// 在这里正式将登陆用户user.id 存到了req._passport.session.user中
// 将req._passport.session指向req.session.passport(默认为passport属性)
// 也就是说 req.session.passport.user为最终的落点
// 这里有一个cb 成功cb() 失败 cb(err)  回到http/request.js/req.login 中处理剩余逻辑
//  => http/request.js/req.login
//  => 执行req.login(user, done);// 如上述过程成功 req.user = user; 并且done(),如若失败 req.user = null; 并且done(err);
// 7 认证过程
// => passport.authenticate();
// => authenticator.js/Authenticator.prototype.authenticate(即就是passport._framework.authenticate方法 也就是middleware/authenticate.js/authenticate方法)
// => 回调到strategy/session.js中的SessionStrategy.prototype.authenticate方法
// => 回调到authenticator.js/Authenticator.prototype.deserializeUser 进行真正序列化的过程 req.user = user(经过this._deserializers执行栈中函数数据库查询后为user对象而不只是user.id)
// => 回调到了strategy/session.js 中的SessionStrategy.prototype.authenticate方法继续执行剩余代码
// => 回到middleware/authenticate.js/authenticate方法中调用 strategy.pass() 进行next(), 或者next(err), 或者callback(err) 完成验证
