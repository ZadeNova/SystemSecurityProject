# SystemSecurityProject
School Project

1) # check your program / code make sure it is working before pushing
2) # update your project before commiting
3) # commit first then push - and write down what u do and ur name
4) # add :

 if session['2fa_status'] == 'Pass' or session['2fa_status'] == 'Nil':

else:
        flash('Please complete your 2FA !', 'danger')
        return redirect(url_for("two_fa"))

 # to all the new app.route , as this can prevent user  from skippping the 2fa !

 5) if u wan prevent user from entering a page that they are not suppose to enter add

 if session['role'] == 'Admin':

 else:
            return redirect(url_for('Userprofile'))
