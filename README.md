# Using has_secure_password

## Overview

It's quite difficult to manage passwords securely. About once a month, there is another big hack in the news, and all the passwords and credit card from some poor site shows up on bittorrent.

Rails provides us with tools to store passwords relatively securely, so that when hackers break into your servers, they don't gain access to users' actual passwords.

## Objectives
  1. Explain why, exactly, it's a bad idea to store passwords in plaintext.
  2. Write code to store and verify hashed, salted passwords.
  3. Use Rails' `has_secure_password` to store and authenticate users login credentials securely.

## The problem with passwords

Let's imagine a `SessionsController#create` method that does very simple authentication. It goes like this:

   def create
     @user = User.find(username: params[:username])
     return head(:forbidden) unless params[:password] == @user.password
     session[:user_id] = @user.id
   end

We load the user row, check to see if the provided password is equal to the password stored in the database, and if it is, we set `user_id` in the `session`.

This is tremendously insecure.

The reason this is tremendously insecure is that you have to store all your users' passwords in the database, unencrypted.

Never do this.

Even if you don't care about the security of your site, people have a strong tendency to reuse passwords. That means that the inevitable security breach of your site will leak passwords which some users also use for Gmail. Your `users` table probably has an `email` column. This means that if I'm a hacker, getting access to your database has given me the Internet equivalent of the house keys and home address for some (probably surprisingly large) percentage of your users.

## Hashing passwords

So how do we store passwords if we can't store passwords?

We store their hashes. A *hash* is a number computed by feeding a string to a *hash function*. Hash functions have the property that they will always produce the same number given the same input. You could write one yourself. Here's one that I just made:

   # dumb_hash(input: string) -> number
   def dumb_hash(input)
     input.bytes.reduce(:+)
   end

My `dumb_hash` function just finds the sum of the bytes that comprise the string. It is a hash function, since it satisfies the criteria that the same string always produces the same result.

We could imagine using this function to avoid storing passwords in the database. Our `User` model and `SessionsController` might look like this:

   # app/models/user.rb
   class User < ActiveRecord::Base
     def password=(new_password)
       self.password_digest = dumb_hash(new_password)
     end

     def authenticate(password)
       return nil unless dumb_hash(password) == password_digest
       self
     end

     private

     def dumb_hash(input)
       input.bytes.reduce(:+)
     end
   end

   # app/controllers/sessions_controller.rb
   class SessionsController < ApplicationController
     def create
       user = User.find_by(username: params[:username])
       authenticated = user.try(:authenticate, params[:pasword])
       return head(:forbidden) unless authenticated
       @user = user
       session[:user_id] = @user.id
     end
   end

In this world, we have saved the passwords' hashes in the database, in the `password_digest` column. We are not storing the passwords themselves.

You can set a user's password by saying `user.password = *new_password*`. Presumably, our `UsersController` would do this, but we're not worrying about it for the moment.

`dumb_hash` is, as its name suggests, a pretty dumb hash function to use for this purpose. It's a poor choice because similar strings hash to similar values. If my password was 'Joshua', you could log in as me by entering the password 'Jnshub'. Since 'n' is one less than 'o' and 'b' is one more than 'a', the output of `dumb_hash` would be the same.

This is known as a *collision*. Collisions are inevitable when you're writing a hash function, since hash functions usually produce either a 32-bit or 64-bit number, and the space of all possible strings is much larger than either `2**32` or `2**64`.

Fortunately, smart people who have thought about this a lot have written a lot of different hash functions which are well-suited to different purposes. And nearly all hash functions are designed with the quality that strings which are similar but not the same hash to significantly different values.

Ruby internally uses [MurmurHash][murmur], which produces better results for this:

    > 'Joshua'.hash
     => -3766180385262328513

    > 'Jnshub'.hash
     => 827642026211689321

But Murmur still isn't ideal, because while it does not produce collisions so readily, it is still not difficult to produce them if that's what you're trying to do.

Instead, Rails uses BCrypt. BCrypt is designed with these properties in mind:
  1. BCrypt hashes similar strings to very different values.
  2. It is a *cryptographic hash*. That means that if you have an output in mind, finding a string which produces that output is designed to be "very difficult". "Very difficult" means "even if Google put all their computers on it, they couldn't do it".
  3. BCrypt is designed to be slow—it is intentionally computationally expensive.

The last two features make BCrypt a particularly good choice for passwords. (2) means that even if an attacker gets your database of hashed passwords, it is not easy for them to turn a hash back into its original string. (3) means that even if an attacker has a dictionary of common passwords to check against, it will still take them a considerable amount of time to check your password dictionary against that list.

## Salt

But what if our attackers have done their homework?

Say I'm a hacker. I know I'm going to break into a bunch of sites and get their password databases. I want to make that worth my while.

Before I do all this breaking and entering, I'm going to find the ten million most common passwords and hash them with BCrypt. If I can do around 1,000 hashes per second, so that's about three hours. Maybe I'll do the top five hundred million just to be sure.

It doesn't really matter that this is going to take long time to run—I'm just doing this once. Let's call this mapping of strings to hash outputs a ["rainbow table"][rainbow_table].

Now, when I get your database, I just look and see if any of the passwords there are in my rainbow table. If they are, then I know the password.

The solution to this problem is *salting* our passwords. A salt is a random string appended to the password before hashing it. It's stored in plain text next to the password, so it's not a secret. But the fact that it's there makes an attacker's life much more difficult: it's very unlikely that I constructed my rainbow table with your particular salt in mind, so I'm back to running the hash algorithm over and over as I guess passwords. And remember, Bcrypt is designed to be expensive to run.

So let's update our `User` model to use bcrypt:

    # Gemfile:
    gem 'bcrypt'

    # app/models/user.rb
    class User < ActiveRecord::Base
      def password=(new_password)
        salt = BCrypt::Engine::generate_salt
	hashed = BCrypt::Engine::hash_secret(new_password, salt)
	self.password_digest = salt + hashed
      end

      # authenticate(password: string) -> User?
      def authenticate(password)
         # Salts generated by generate_salt are always 29 chars long.
         salt = password_digest[0..28]
	 hashed = BCrypt::Engine::hash_secret(password, salt)
	 return nil unless (salt + hashed) == self.password_digest
      end
    end

Our `users.password_digest` column actually stores two values: the salt, and the actual return value of BCrypt. We just concat them together in the column, and use our knowledge of the length of salts—generate_salt always produces 29 character strings—to separate them.

After we've loaded the User, we find the salt which we previously stored in their `password_digest` column. We run the password we were given in `params` through BCrypt, along with the salt we read from the database. If the results match, you're in. If they don't, no dice.

## Rails makes it easier

You don't have to deal with all this yourself. Rails provides a method called `has_secure_password` which you can use on your ActiveRecord models to handle all this. It looks like this:

    class User < ActiveRecord::Base
      has_secure_password
    end

You'll need to add 'bcrypt' to your Gemfile if it isn't already.

[`has_secure_password`][has_secure_password] adds two fields to your model: `password` and `password_confirmation`. These fields don't correspond to database columns! Instead, the method expects there to be a `password_digest` column defined in your migrations.

`has_secure_password` also adds some `before_save` hooks to your model. These compare `password` and `password_confirmation`. If they match (or if `password_confirmation` is nil), then it updates the `password_digest` column pretty much exactly like our example code before did.

These fields are designed to make it easy to include a password confirmation box when creating or updating a user. All together, our very app might look like this:

    # app/views/user/new.html.erb
    <%= form_for :user, url: '/users' do |f| %>
      Username: <%= f.text_field :username %>
      Password: <%= f.password_field :password %>
      Password Confirmation: <%= f.password_field :password_confirmation %>
      <%= f.submit "Submit" %>
    <% end %>

    # app/controllers/users_controller.rb
    class UsersController < ApplicationController
      def create
        user = User.new(user_params).save!
      end

      private

      def user_params
        params.require(:user).permit(:name, :email, :password, :password_confirmation)
      end      
    app

    # end/controllers/sessions_controller.rb
    class SessionsController < ApplicationController
      def create
        @user = User.find(username: params[:username])
        return head(:forbidden) unless params[:password] == @user.password
        session[:user_id] = @user.id
      end
    end

    # app/models/user.rb
    class User < ActiveRecord::Base
      has_secure_password
    end   

## Resources
  * [Wikipedia — Murmur Hash][murmur]
  * [Wikipedia — Rainbow Table][rainbow_table]
  * [bcrypt USENIX paper]: https://www.usenix.org/legacy/event/usenix99/provos/provos.pdf
  * [Rails documentation — has_secure_password][has_secure_password]

[murmur]: https://en.wikipedia.org/wiki/MurmurHash
[rainbow_table]: https://en.wikipedia.org/wiki/Rainbow_table
[bcrypt]: https://www.usenix.org/legacy/event/usenix99/provos/provos.pdf
[has_secure_password]: http://api.rubyonrails.org/classes/ActiveModel/SecurePassword/ClassMethods.html
