/**
 * gt4-loader.js — entry point.
 *
 */
!function(e) {
    "use strict";
    if (void 0 === e)
        throw Error("Geetest requires browser environment");
    var t = e.document
      , o = e.Math
      , r = t.getElementsByTagName("head")[0];
    function n(e) {
        this._obj = e
    }
    function a(e) {
        var t = this;
        new n(e)._each(function(e, o) {
            t[e] = o
        })
    }
    n.prototype = {
        _each: function(e) {
            var t = this._obj;
            for (var o in t)
                t.hasOwnProperty(o) && e(o, t[o]);
            return this
        },
        _extend: function(e) {
            var t = this;
            new n(e)._each(function(e, o) {
                t._obj[e] = o
            })
        }
    },
    a.prototype = {
        apiServers: ["gcaptcha4.geetest.com", "gcaptcha4.geevisit.com"],
        staticServers: ["static.geetest.com", "static.geevisit.com", "dn-staticdown.qbox.me"],
        protocol: "http://",
        typePath: "/load",
        fallback_config: {
            bypass: {
                staticServers: ["static.geetest.com", "static.geevisit.com", "dn-staticdown.qbox.me"],
                type: "bypass",
                bypass: "/v4/bypass.js"
            }
        },
        _get_fallback_config: function() {
            return c(this.type) ? this.fallback_config[this.type] : this.fallback_config.bypass
        },
        _extend: function(e) {
            var t = this;
            new n(e)._each(function(e, o) {
                t[e] = o
            })
        }
    };
    var c = function(e) {
        return "string" == typeof e
    }
      , i = /Mobi/i.test(navigator.userAgent)
      , s = {}
      , l = {}
      , u = function(e, t) {
        if ("function" == typeof e) {
            var o = Array.prototype.slice.call(arguments, 2);
            return Function.prototype.bind ? e.bind(t, o) : function() {
                var r = Array.prototype.slice.call(arguments);
                return e.apply(t, o.concat(r))
            }
        }
    }
      , f = Object.prototype.toString
      , p = function(e, o, n) {
        var a = t.createElement("script");
        a.charset = "UTF-8",
        a.async = !0,
        /static\.geetest\.com/g.test(e) && (a.crossOrigin = "anonymous"),
        a.onerror = function() {
            o(!0),
            c = !0
        }
        ;
        var c = !1;
        a.onload = a.onreadystatechange = function() {
            c || a.readyState && "loaded" !== a.readyState && "complete" !== a.readyState || (c = !0,
            setTimeout(function() {
                o(!1)
            }, 0))
        }
        ,
        a.src = e,
        r.appendChild(a),
        setTimeout(function() {
            c || (a.onerror = a.onload = null,
            a.remove && a.remove(),
            o(!0))
        }, n || 1e4)
    }
      , g = function(e) {
        if (!e)
            return "";
        var t = "?";
        return new n(e)._each(function(e, o) {
            (c(o) || "number" == typeof o || "boolean" == typeof o) && (t = t + encodeURIComponent(e) + "=" + encodeURIComponent(o) + "&")
        }),
        "?" === t && (t = ""),
        t.replace(/&$/, "")
    }
      , d = function(e, t, o, r) {
        t = t.replace(/^https?:\/\/|\/$/g, "");
        var n, a = (0 !== (n = (n = o).replace(/\/+/g, "/")).indexOf("/") && (n = "/" + n),
        n + g(r));
        return t && (a = e + t + a),
        a
    }
      , h = function(t, r, n, a, c, i, s) {
        var l = function(f) {
            if (s) {
                var g = "geetest_" + (parseInt(1e4 * o.random()) + new Date().valueOf());
                e[g] = u(s, null, g),
                c.callback = g
            }
            p(d(r, n[f], a, c), function(t) {
                if (t) {
                    if (g)
                        try {
                            e[g] = function() {
                                e[g] = null
                            }
                        } catch (e) {}
                    f >= n.length - 1 ? i(!0) : l(f + 1)
                } else
                    i(!1)
            }, t.timeout)
        };
        l(0)
    }
      , y = function(t, r, n, a) {
        h(n, n.protocol, t, r, {
            captcha_id: n.captchaId,
            challenge: n.challenge || "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, function(e) {
                var t = 16 * o.random() | 0;
                return ("x" === e ? t : 3 & t | 8).toString(16)
            }),
            client_type: i ? "h5" : "web",
            risk_type: n.riskType,
            call_type: n.callType,
            lang: n.language ? n.language : "Netscape" === navigator.appName ? navigator.language.toLowerCase() : navigator.userLanguage.toLowerCase()
        }, function(e) {
            e && "function" == typeof n.offlineCb ? n.offlineCb() : e && a(n._get_fallback_config())
        }, function(t, o) {
            "success" == o.status ? a(o.data) : (o.status,
            a(o)),
            e[t] = void 0;
            try {
                delete e[t]
            } catch (e) {}
        })
    }
      , v = function(e, t, o) {
        if ("function" == typeof t.onError)
            t.onError({
                desc: o.desc,
                msg: o.msg,
                code: o.code
            });
        else
            throw Error({
                networkError: "网络错误",
                gtTypeError: "gt字段不是字符串类型"
            }[e])
    };
    (e.Geetest || t.getElementById("gt_lib")) && (l.slide = "loaded"),
    e.initGeetest4 = function(t, o) {
        var r, c = new a(t);
        t.https ? c.protocol = "https://" : t.protocol || (c.protocol = e.location.protocol + "//"),
        t.hasOwnProperty("language") && c._extend(t),
        "object" == typeof (r = t.getType) && null !== r && c._extend(t.getType),
        y(c.apiServers, c.typePath, c, function(r) {
            t.hasOwnProperty("custom_theme") && r.custom_theme._brightness !== t.custom_theme._brightness && (r.custom_theme._brightness = t.custom_theme._brightness),
            t.hasOwnProperty("language") && r.language !== t.language && (r.language = t.language);
            var r = function e(t, o) {
                if (t !== Object(t) || "[object Date]" == f.call(t) || "[object RegExp]" == f.call(t) || "[object Boolean]" == f.call(t) || "function" == typeof t)
                    return o ? t.replace(/(\S)(_([a-zA-Z]))/g, function(e, t, o, r) {
                        return t + r.toUpperCase() || ""
                    }) : t;
                if ("[object Array]" == f.call(t))
                    for (var r = [], n = 0; n < t.length; n++)
                        r.push(e(t[n]));
                else {
                    var r = {};
                    for (var a in t)
                        t.hasOwnProperty(a) && (r[e(a, !0)] = e(t[a]))
                }
                return r
            }(r);
            if ("error" === r.status)
                return v("networkError", c, r);
            var a = r.type;
            c.debug && new n(r)._extend(c.debug);
            var i = function() {
                c._extend(r),
                o(new e.Geetest4(c))
            };
            s[a] = s[a] || [];
            var u = l[a] || "init";
            if ("init" === u)
                l[a] = "loading",
                s[a].push(i),
                r.gctPath && h(c, c.protocol, Object.hasOwnProperty.call(c, "staticServers") ? c.staticServers : r.staticServers || c.staticServers, r.gctPath, null, function(e) {
                    e && v("networkError", c, {
                        code: "60205",
                        msg: "Network failure",
                        desc: {
                            detail: "gct resource load timeout"
                        }
                    })
                }),
                h(c, c.protocol, Object.hasOwnProperty.call(c, "staticServers") ? c.staticServers : r.staticServers || c.staticServers, r.bypass || r.staticPath + r.js, null, function(e) {
                    if (e)
                        l[a] = "fail",
                        v("networkError", c, {
                            code: "60204",
                            msg: "Network failure",
                            desc: {
                                detail: "js resource load timeout"
                            }
                        });
                    else {
                        l[a] = "loaded";
                        for (var t = s[a], o = 0, r = t.length; o < r; o += 1) {
                            var n = t[o];
                            "function" == typeof n && n()
                        }
                        s[a] = []
                    }
                });
            else {
                if ("loaded" === u)
                    return i();
                "fail" === u ? v("networkError", c, {
                    code: "60204",
                    msg: "Network failure",
                    desc: {
                        detail: "js resource load timeout"
                    }
                }) : "loading" === u && s[a].push(i)
            }
        })
    }
}(window);
