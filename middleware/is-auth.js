module.exports = (req, res, next) => {
    if(!req.session.isLoggedIn) {
        console.log("Sessão não iniciada. Favor realizar login para continuar.")
        return res.redirect("/login");
    }
    next();
}