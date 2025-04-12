# Introduction

Games are everywhere, and they’re increasingly played on connected web devices and within desktop and mobile browser environments. As browser-based games become more popular, players are turning to sites like Facebook to discover simple, casual games that don’t require a disc or much up-front setup to play. A game is just another link to click through.

During the past decade, improvements to Adobe’s Flash plug-in contributed to the growth of the web browser as a gaming platform. Most browsers supported Flash, giving game developers access to a powerful platform that approached the dream of *write once, run anywhere*. HTML-based games have been around about as long, and you may even have played some (possibly without noticing). However, until recently, the use of HTML and JavaScript as a gaming platform played second fiddle to Flash due to graphics, sound, and speed limitations. But browsers and mobile gaming platforms have vastly improved, and the status quo is changing. Mobile operating systems have steered away from Flash as a supported plug-in, and as a result, game developers need tools that provide similar performance and flexibility while retaining the ubiquity that Flash had.

Browsers have also seen a rapid improvement in graphical and sound capabilities over the past few years. The rise in power of HTML mirrors increasing demand for a platform that delivers rich gaming experiences and has the backing of multiple platform providers. A well-supported, open platform is considered less likely to fall foul of commercial controls and a walled-garden mentality, and HTML5 is such a platform.

However, in my experience, many game developers come to HTML5 looking to build the same type of games they would have built in Flash. HTML5 is certainly one of the best options: it has a huge user base (anyone with a modern web browser), and HTML5 and Flash have many similar capabilities and constraints. Despite this similarity, thinking of HTML5 as a Flash replacement is likely to lead to disappointing product launches and missed opportunities. This is because the strengths of one do not directly map to the strengths of the other. Also, HTML5 is still in a relatively early stage of development. The platform is advancing rapidly, and it can be difficult to keep up with which new features are supported from month to month.

Much as with building a good web application, the key to making a successful game is to understand your platform’s capabilities and restrictions. You have to design and build games that maximize the platform’s potential while avoiding or minimizing its limitations. This book is intended as a first step in understanding what you can achieve with JavaScript, HTML, and CSS and introducing the methods by which you can do so.

# Why Build HTML5 Games?

Before I dive into specifics about this book, let’s step back and consider why you might want to create a game on the HTML5 platform in the first place.

## Using Skills You Already Have

Web developers who are skilled with JavaScript and CSS will feel more confident about stepping into HTML5 game development. Deploying HTML and JavaScript files is also a familiar process, and you can build online components using server-side languages that overlap with web development.

But if you throw yourself into writing C++ or Objective-C, the combination of a new language, a new development environment, and new thought processes required for game development can be a steep learning curve. In short, the conceptual leap needed to move from web development to HTML5 game development is relatively minor compared to that needed for other game technologies.

## Multi-environment Development

Many platforms have promised the ability to write once and run anywhere, and in my opinion, HTML5 is the closest that any technology has come to delivering. Whether you develop for a desktop browser or a packaged mobile application, your coding styles won’t vary much, nor will the basic technology of representing objects on the screen and having a user interact with them. Of course, there will always be some environment-specific differences, especially if code is to take advantage of the features and benefits that one environment may have to offer over another.

Still, games written in HTML5 and JavaScript have a very good chance of working with minimal changes across multiple operating systems. This allows for simultaneous releases and single development teams rather than a team per system. You can also code and test in a desktop browser, even if the final environment will be different.

## A Rapidly Improving Platform

HTML5 is constantly and rapidly improving. JavaScript’s processing speed is also increasing, and sophisticated interpreters are approaching native speeds for some operations. Given the increases in CPU speed in the past 10 years, games written in JavaScript can perform better than many of those written in native code just a few years ago.

With the efforts of browser vendors and hardware manufacturers, this improvement trajectory will only continue, and there’s no doubt that HTML5 is growing as a viable gaming platform. Whether HTML5 game development will grow as a fast development environment for immersive 3D games on mobile or desktop browsers or as a rapid prototyping environment for casual game developers, or even migrate into the console environment through Android or other devices, it’s an exciting time to be a JavaScript programmer. Now is the time to build on the knowledge you will gain in this book and experiment with the capabilities of HTML5 and JavaScript as an open game development platform.

# About This Book

This book cannot demonstrate the full range of possible HTML5 games and therefore does not explore the capabilities of HTML5 and JavaScript to the fullest. Instead, I concentrate on creating a single casual game, like those many developers have produced for years with Adobe Flash. These games are generally two-dimensional and single player with relatively short game loops. Advances in 3D capabilities, such as WebGL, mean that large, complex, immersive multiplayer games are either possible now or just around the corner, but a casual game project is a more natural place for a game developer to start. Simple projects also make it easier to illustrate the fundamental principles involved in building a game.

## Who This Book Is For

This book is intended for web developers familiar with HTML, CSS, and JavaScript who want to translate their existing skills to game development. At the bare minimum, you should know how to program, and ideally, you should know the basics of JavaScript. You should also have access to a web server and development environment of your own or be able to set those up for yourself.

If you have some background knowledge in either web or gaming technologies, want to know what you could achieve with HTML5, and have the enthusiasm to learn and experiment, you should be able to work through this book. By the end, you’ll have a clear idea of how to approach HTML5 game development projects and a good overview of the core processes involved in making games in general.

## Overview

Throughout the book, you will develop a simple bubble-popping game meant to be played in a browser. With each chapter, I’ll introduce new concepts by putting them into practice.

In **[Part I](pt01.html "Part I. Building a Game with HTML, CSS, and JavaScript"): Building a Game with HTML, CSS, and JavaScript**, which includes the first four chapters of the book, you’ll build a complete game using HTML, CSS, and JavaScript.

*   **[Chapter 1](ch01.html "Chapter 1. Preparation and Setup"): Preparation and Setup** looks at the tools we’ll need, including the jQuery and Modernizr script libraries, how to debug, and how to put the game’s file structure in place.

*   **[Chapter 2](ch02.html "Chapter 2. Sprite Animation Using jQuery and CSS"): Sprite Animation Using jQuery and CSS** describes how to move HTML elements around the screen in response to mouse clicks. In the context of the game, this means shooting an image from a starting position to the coordinates that the player clicks.

*   **[Chapter 3](ch03.html "Chapter 3. Game Logic"): Game Logic** has you draw the game board and set up much of the game logic, including firing a bubble and collision detection.

*   **[Chapter 4](ch04.html "Chapter 4. Translating Game State Changes to the Display"): Translating Game State Changes to the Display** teaches you to make the game respond to the collisions that we detected in [Chapter 3](ch03.html "Chapter 3. Game Logic") and add more game logic to pop groups of bubbles. This introduces some basic animation within an object by way of a popping effect.

In **[Part II](pt02.html "Part II. Enhancements with HTML5 and the Canvas"): Enhancements with HTML5 and the Canvas**, you’ll improve the game you created in [Part I](pt01.html "Part I. Building a Game with HTML, CSS, and JavaScript") with features from HTML5 and the canvas.

*   **[Chapter 5](ch05.html "Chapter 5. CSS Transitions and Transformations"): CSS Transitions and Transformations** shows you how to use CSS3 to achieve some of the results that you used jQuery for in previous chapters.

*   **[Chapter 6](ch06.html "Chapter 6. Rendering Canvas Sprites"): Rendering Canvas Sprites** shows you how to render the game entirely within the HTML5 canvas, including moving objects across the screen and animation effects.

*   **[Chapter 7](ch07.html "Chapter 7. Levels, Sound, and More"): Levels, Sound, and More** tidies up some loose ends in the game logic, introduces smoother animation techniques, and shows you how to implement sound effects and save the player’s score.

*   **[Chapter 8](ch08.html "Chapter 8. Next Steps in HTML5"): Next Steps in HTML5** discusses some useful technologies that you didn’t need to use in the casual game you developed. It suggests areas for future reading, such as Web Workers and WebGL for 3D games, and discusses important issues, such as memory management and optimizing for speed.

*   Finally, the **Afterword** provides some ideas to improve your HTML5 game-programming skills. For example, you could continue to improve on the game you built in this book, or you could start developing game ideas of your own.

All the code created in this book is available to download from *[http://buildanhtml5game.com/](http://buildanhtml5game.com/)*, where you can also see a version of the game you’ll be building in action. And at the end of each chapter, I include exercises to test your skills and spark ideas for improving the *Bubble Shooter* game.

## Depth of Coverage

Because this book focuses on casual game development, I won’t go into detail about WebGL, three-dimensional modeling, shaders, textures, lighting, and other techniques associated with more complex games like first-person action shooters or massively multiplayer online role-playing games (MMORPGs). These subjects fill books all on their own. However, you’ll find most principles of building casual games useful in more technically demanding situations. I recommend keeping your initial projects achievable and working toward something more complex after you have a few releases under your belt. Once you’ve completed a couple of projects using HTML, CSS, and the canvas, you’ll be equipped to learn more about WebGL if that’s a direction you want to pursue; however, you may find that you have more than enough development opportunities in the casual game space.

This book introduces you to game development techniques, but it is not an exhaustive reference for the Application Programming Interfaces (APIs) you’ll use. Neither is it a complete guide to HTML5: only the features that are most relevant to game development are covered. The Internet is full of material that not only provides more detail but is also updated to reflect the ever-changing browser environment. I’ll highlight useful resources and documentation as appropriate.

Likewise, this is not a book about game design. I’ll teach you *how* to build, but not *what* to build. The skills you learn should give you a starting point from which you can bring your own ideas to life or start to work on projects designed by others.

## How to Use This Book

Throughout the book, I’ll help you create the HTML, CSS, and JavaScript files that form the *Bubble Shooter* game. You should keep the file *index.html* (created in [Chapter 1](ch01.html "Chapter 1. Preparation and Setup")) open in at least one browser at all times as you work through the tutorial. That way, you can refresh the page to see how your changes to the code have altered the game.

I encourage you to run the *Bubble Shooter* on a local development web server rather than viewing it from the filesystem so you can access it as a real user would and see how it looks on mobile devices.

### Note

*If you don’t want to type the example code, just download the source code (from* [http://buildanhtml5game.com/](http://buildanhtml5game.com/)*) and work from the game files for the chapter you’re reading.*

Once you’ve decided how you want to load the *Bubble Shooter* files for testing, jump into [Chapter 1](ch01.html "Chapter 1. Preparation and Setup") to start making your first game!