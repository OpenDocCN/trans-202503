# Appendix A. Afterword

Hopefully, working through this book has taught you how simple it can be to develop a game with HTML5 and JavaScript and has given you some insight into these technologies’ potential. The next question is: where to next? The answer is: go and make more games!

With your new skills and HTML5, CSS, and JavaScript reference material on the Internet, you should be able to tackle just about any kind of game that’s possible with HTML5, although I recommend making your next project relatively small and achievable. Most developers have a list of unfinished projects longer than their list of finished ones, so start with a game that will let you put a tick in the right column.

If you already have some game ideas and think you can build them, by all means dive straight in! In case you’re wondering where to go, here are a few suggestions to help you hone your skills and build a portfolio.

# Improving Bubble Shooter

*Bubble Shooter* is pretty nifty already, but we all know it could be better. Any game always has room for improvement! Here are some ideas:

*   Add power-ups and bonus points that drop when bubbles are popped and that the user has to click to collect.

*   Add more bubble colors to later levels.

*   Create grid patterns in different sizes and layouts.

*   Implement side walls so the player can bounce fired bubbles off the sides.

You shouldn’t need to write an entirely new game to add these features, and with the bulk of *Bubble Shooter* in place already, you can really focus on refining them. Throw in a few creative ideas of your own, and you’ll have a game that people can’t stop playing!

# Creating a Whole New Game

You can learn a lot by spending time polishing a game such as *Bubble Shooter*, but to build your confidence as a game developer, there’s nothing better than building as many games as you can. You can either create your own new game ideas or, to fast-track to the programming process, work with some existing games and try to figure out how they’re made. I’ll describe a few suggestions for basic game ideas that you’ll be able to construct with your new skills.

## Match-3

Match-3 games, such as *Bejeweled* and *Candy Crush*, never seem to go out of fashion, and they present both a well-defined technical challenge and a demanding user interface one. Consider the problem of a set of gems exploding and dropping, which in turn causes more gems to drop and explode, and so on. Visualize algorithms to handle the cascading effects and consider what happens if the user tries to swap a gem while all of this is happening. Will you let players do that? Try building the best game of this type that you can, and then, once you have it working, play *Bejeweled* or one of the other popular implementations, identify the features you think make the experience fun, and try to add similar polish to your game. Subtle but effective touches really make all the difference.

## Solitaire

Card games are simpler than other games graphically, but they pose enough user interface and game logic challenges that it’s worth working through one. Once the game logic is in place, you can offer users customized deck backs and animations to give your game personality. Be sure to obfuscate your code so that players can’t peek at the deck state while playing!

## A Platform Game

A platform game is a big step up from the types of games mentioned earlier. You’ll need to implement some basic physics for the main character (although I wouldn’t try to implement real physics for the entire game) and some kind of scrolling, either just sideways or possibly in both dimensions. The level design can remain simple: define an entrance point and an exit point and make the player cross between the two. By the end, you’ll start thinking more in terms of reusing code for future games, and you’ll have solved challenges such as animating a moving figure.

## A Simple Physics Game

*Angry Birds* was a huge hit, which makes it all the more surprising that the basic mechanics are so simple to re-create. *Angry Birds* uses a physics engine called Box2D, and there’s a free version available for JavaScript called Box2dWeb. You can find the code and documentation at *[https://code.google.com/p/box2dweb/](https://code.google.com/p/box2dweb/)*. The examples that you’ll find online aren’t always simple to follow, and adding physics to a game is challenging. I recommend Seth Ladd’s tutorial for a step-by-step introduction to the library at *[http://blog.sethladd.com/2011/08/box2d-orientation-for-javascript.html](http://blog.sethladd.com/2011/08/box2d-orientation-for-javascript.html)*.

# Joining a Game Development Team

If none of the ideas discussed so far captures your imagination, and you’re struggling to come up with a game concept of your own, consider finding a game designer who’s looking for someone to help realize their creations. Sites such as Meetup (*[http://meetup.com/](http://meetup.com/)*) are a good place to look for game development groups. You can meet and perhaps collaborate with both established and aspiring game developers.

With HTML5, an individual or a small team can create games that mass audiences can play on desktop and mobile devices more easily than ever before. Grab the opportunity—go forth and make games!