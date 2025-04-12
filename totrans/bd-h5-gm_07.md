# Chapter 5. CSS Transitions and Transformations

So far, we’ve created a bare-bones game with HTML, CSS, and JavaScript: we can fire and pop bubbles, and our user interface feels responsive. We achieved this through Document Object Model (DOM) manipulation with a lot of jQuery help.

In this chapter, we’ll explore CSS transitions and transformations, which can improve game performance and let you create a wider range of effects, such as rotating and scaling elements.

# Benefits of CSS

CSS provides a set of transformation and transition attributes that you can use to animate changes to CSS properties, such as the `left` or `top` coordinates of an element. Rather than using JavaScript to handle animations frame by frame, as we’ve done so far, CSS transitions are specified in the style sheet or as styles attached to DOM elements. An animation is then initiated by making a single change to a CSS property rather than making many incremental changes to a property, as JavaScript animations require.

CSS animations are handled by the browser’s rendering engine rather than by the JavaScript interpreter, freeing up CPU time for running other JavaScript code and ensuring the smoothest animation possible on the device at the time. On systems with graphics processors, the effects are often handled entirely by the graphics processor, which means less work for the JavaScript code you are running and can reduce the load on the CPU even further, resulting in higher frame rates. As a result, the animation will run at the highest frame rate possible for the device it’s displayed on.

We’ll use CSS to add some simple transitions to user-interface elements and then replace our jQuery animations with transformations, and we’ll do this while maintaining the cross-browser compatibility that we’ve achieved thus far.

# Basic CSS Transitions

The first CSS animation we’ll focus on is the transition. A *transition* defines how a style property of an object should change from one state to a new one. For example, if we change the `left` property of a DOM element from 50 pixels to 500 pixels, it will instantly change position on the screen. But if we specify a transition, we can instead make it move gradually across the screen. A CSS transition specifies a property or properties to animate, how the animation should take place, and how long the animation should take.

Transitions generally apply to any CSS property that has a numerical value. For example, animating the `left` property, as mentioned earlier, is possible because intermediate values between the beginning and end can be calculated. Other property changes, such as between `visibility : hidden` and `visibility : visible`, are not valid properties for a transition because intermediate values cannot be calculated. However, we could make an element fade in by animating the `opacity` property from 0 to 1.

Colors are also valid properties to animate, because hex values are also numbers (each contains three pairs, and each pair represents red, green, or blue) that can be gradually changed from one value to another. You can find a list of all the properties that can be animated with transitions at *[https://developer.mozilla.org/en-US/docs/Web/CSS/CSS_animated_properties/](https://developer.mozilla.org/en-US/docs/Web/CSS/CSS_animated_properties/)*.

## How to Write a Transition

To animate a `div` using a transition, add a CSS `transition` property to it. A `transition` property includes the following:

*   ****CSS properties to apply the transition to****. These can be any valid CSS properties that you want to animate, such as `top`, `left`, `font-size`, or just `all`, which applies transitions to all valid property changes.

*   ****Duration****. How long (in seconds) the transition will take.

*   ****Easing****. Tells a property how fast to change over the transition duration. For example, an element might move from one point to another at a smooth pace, or it could accelerate at the beginning and then decelerate toward the end, as in [Figure 5-1](ch05.html#graph_showing_movement_with_no_easing_an "Figure 5-1. Graph showing movement with no easing and movement with easing in (at the start of the animation) and out (at the end)."). You can apply easing to other properties you want to change, too, including color.

    ![Graph showing movement with no easing and movement with easing in (at the start of the animation) and out (at the end).](httpatomoreillycomsourcenostarchimages2184527.png.jpg)

    Figure 5-1. Graph showing movement with no easing and movement with easing in (at the start of the animation) and out (at the end).

*   ****Start delay****. Specifies the number of seconds to wait to start the transition. The most common value is 0 (or empty), which means start immediately.

We’ll write a transition definition just like any other CSS rule, and when we want the transition to occur, we’ll make a change to the CSS property that we want to animate. To move a `div` or other HTML element smoothly across the screen, we set the `top` and `left` coordinates to new values:

```
transition: top 1s, left 2s (etc)
```

As an example, we’ll make the New Game button move down the screen. Add the following to *main.css*:

*main.css*

```
  .button
  {
    transition: ➊all ➋.8s ➌ease-in-out ➍1s;
➎  -moz-transition: all .8s ease-in-out 1s;
    -webkit-transition: all .8s ease-in-out 1s;
    -ms-transition: all .8s ease-in-out 1s;
  }
```

The `transition` definition’s first value ➊ states which property (or properties) the transition applies to. Using `all` applies the transition to every property; think of it as a wildcard. The second value ➋ is the duration of the transition in seconds. The third value ➌ is the easing: `ease-in-out` produces a smooth transition with an initial acceleration and ending deceleration. Finally, we add a delay ➍ of 1 second before the animation runs. The next three lines beginning at ➎ provide the same specification but with vendor-specific prefixes for cross-browser support. These are needed for older browsers; newer browsers use the unprefixed version once the tag definition is considered to be stable.

To guarantee your game will run on a certain browser, always include the correct vendor-specific prefix. Just be sure that whenever you change a transition’s property, you also change it in the transition definition for each browser.

Fortunately, the rule is simple: the browser-specific versions of `transition` are just copies of the regular version with one of the following prefixes:

*   `-moz-` for Mozilla browsers, such as Firefox

*   `-webkit-` for Webkit browsers, such as Chrome and Safari

*   `-ms-` for Microsoft Internet Explorer

Reload the page and then type the following into the JavaScript console:

```
$(".but_start_game").css("top",100)
```

You should see a pause, and then the button will smoothly slide up the screen. The effect is more or less identical to an `animate` call, but we changed only the CSS value.

Delete the CSS definition for `.button` now because we’re going to apply a more useful effect.

## Color-Changing Buttons

Let’s apply transitions to spice up our user interface! We’ll animate a button without a single line of JavaScript; instead, we’ll use a `transition` definition and the `hover` pseudo-class that you’re probably familiar with for creating rollover button effects.

First, we’ll add a rollover state to the New Game button with a CSS amendment. Add the following to *main.css* now:

*main.css*

```
  .button
  {
    transition: ➊background-color ➋.3s ➌ease-in-out;
➍  -moz-transition: background-color .3s ease-in-out;
    -webkit-transition: background-color .3s ease-in-out;
    -ms-transition: background-color .3s ease-in-out;
  }
    .button:hover
    {
      background-color: #900;
    }
```

The `transition` definition’s first value ➊ states which property (or properties) the transition applies to. We’re applying it to the `background-color` property, which is written exactly as it would appear as a standard CSS rule. The second value ➋ is the length of the transition in seconds. The third value ➌ is once again the easing, set to `ease-in-out`.

Other types of easing include `ease`, `linear`, or just `ease-in` or `ease-out`. But all of these shorthand descriptions are actually aliases for specific definitions of `cubic-bezier`, which you can use to indicate any transition curve you like. The `cubic-bezier` easing function accepts four decimal numbers to define a graph; for example,

```
transition: background-color .3s ease-in-out;
```

is identical to

```
transition: background-color .3s cubic-bezier(0.42, 0, 0.58, 1.0)
```

Bézier curves are described by specifying the coordinates of two points that form the tangent line of the beginning and the end parts of the curve, respectively. These are shown as P1 and P2 in [Figure 5-2](ch05.html#two_points_that_specify_a_beacutezier_cu "Figure 5-2. The two points that specify a Bézier curve are P1 and P2.").

![The two points that specify a Bézier curve are P1 and P2.](httpatomoreillycomsourcenostarchimages2184529.png.jpg)

Figure 5-2. The two points that specify a Bézier curve are P1 and P2.

The values specified in the CSS are the coordinates of P1 and P2, which are always between 0 and 1\. You won’t specify P0 and P3 because they’re always the origin (0,0) and (1,1), respectively. The angle of P1 and P2 from the vertical axis determines the slope of the curve, and the length of the lines from P0 to P1 and P2 to P3 determines how pronounced the curvature will be.

Unless you want a specific easing, `ease-in-out` or `linear` will often do just fine. But for more complex transitions, some online tools will help you create `cubic-bezier` curves based on visual graphs and input values. One such website is *[http://cubic-bezier.com/](http://cubic-bezier.com/)*, which allows you to tweak values and watch the animation to see how the numbers translate to a movement transition.

The three lines, starting after the initial transition definition at ➍, are vendor-specific transition definitions, which I made sure to include so the transition works properly in different browsers. The CSS standard is still considered a work in progress, and browser manufacturers have adopted their own prefixes to avoid potential conflicts with how the standard is implemented when it’s finalized.

The single-line format I’ve used so far is the most compact way to specify a transition, but you could also specify the properties individually:

```
transition-property: background-color;
transition-duration: .3s;
transition-timing-function: ease-in-out;
```

I recommend sticking with the compact approach most of the time. Otherwise, you’d need all the CSS standard lines plus the three vendor-specific copies of each, which would quickly clutter your style sheet.

Reload the page and hover over the New Game button. You should see a gentle change in color from light to darker red. That’s a nice effect, and you didn’t write any JavaScript! But there’s still more you can do to add effects using CSS only.

# Basic CSS Transformations

The second powerful feature of CSS we’ll look at is transformations. *Transformations* allow you to manipulate an object’s shape. In most browsers, it’s possible to transform an object in either two dimensions or three and to skew, distort, and rotate it in any way that can be described by a three-dimensional matrix. You can animate transformations with transitions or let them stand alone; for example, to display a button at an angle, you might let the viewer watch it rotate, or you might just render the button askew.

## How to Write a Transformation

Some simple CSS transformations include:

*   Translations by (*x*,*y*) or even (*x*,*y*,*z*) coordinates in 3D

*   Scaling by dimensions along the *x-*, *y-*, and *z*-axes

*   Rotating in place by an angle along any of the *x*-, *y*-, or *z*-axes

*   Skewing along the *x*- or *y*-axis

*   Adding 3D perspective

You can transform by a 2D or even a 3D matrix. Transforming by a matrix involves some calculation of the math involved. If you want to explore it in more depth, some references are available online, such as *[https://developer.mozilla.org/en-US/docs/Web/CSS/transform/](https://developer.mozilla.org/en-US/docs/Web/CSS/transform/)*.

## Scaling a Button

In this section, we’ll make the New Game button a bit more dynamic by adding an enlarging effect on top of the current color change. Make the following addition to the `.button:hover` definition in *main.css*:

*main.css*

```
  .button:hover
  {
    background-color: #900;
➊  **transform: scale(1.1);**
    **-moz-transform: scale(1.1);**
    **-webkit-transform: scale(1.1);**
    **-ms-transform: scale(1.1);**
  }
```

The entire transformation is primarily contained in one `transform` line ➊. The transformation is specified as scaling by a factor of 1.1—a size increase of 10 percent. The three lines that follow do the same thing but use the identical vendor-specific prefixes you used in the `transition` definition.

We just want to scale the New Game button, so reload the page and then mouse over the button again. The scaling should work but not as a smooth animation. Although the color still changes gradually in response to the mouse hover, the button’s size jumps in a single step. We’ll amend the transition definition to apply to the transform as well as the background color.

To achieve this task, we could simply change the `.button` definition so the `transition` property affects every CSS property:

```
transition: **all** .3s ease-in-out;
```

This definition applies the `ease-in-out` effect to all of the button’s CSS properties that it’s possible to apply transitions to. Now if any of those properties change after the DOM is rendered, the button will be animated with a 300-millisecond transition effect on that property. But what if you don’t want all button animations to happen at the same rate?

In that case, you could specify multiple properties by adding a comma-separated definition:

```
transition: background-color .2s ease-in-out**, transform 0.2s ease-in-out;**
```

This solution also minimizes side effects if we want to change any other CSS properties on the fly without having them animate automatically.

When you apply transitions to individual `transform` properties in CSS, you still need to specify vendor-specific versions within each `transition` definition. Therefore, the full button definition needs to be this:

```
.button
{
  transition: background-color .3s ease-in-out**, transform .2s ease-in-out**;
  -moz-transition: background-color .3s ease-in-out**, -moz-transform .2s**
**ease-in-out**;
  -webkit-transition: background-color .3s ease-in-out**, -webkit-transform .2s**
**ease-in-out**;
-ms-transition: background-color .3s ease-in-out**, -ms-transform .2s ease-**
**inout**;
}
```

Make this change in *main.css*, reload the page, and mouse over the button again. Now, both the background color and scale should change in a smooth transition.

CSS transitions and transformations are useful for simple animations and especially for mouseover effects on user-interface elements, such as buttons. However, they’re useful for more than just adding a bit of sparkle to the user interface: we can also use them to animate sprites, including the fired bubbles in the game.

# CSS Transitions in Place of jQuery animate

Now, when a player fires a bubble, it leaves the firing point and moves in a straight line toward its destination. Any fired bubble follows a path simple enough that a CSS transition can handle that animation easily, and making the switch will remove some of the load from JavaScript.

The hard-coded CSS transition we used for the button hover effect, where the transition is defined in the style sheet, won’t work for bubble movement because the duration of the transition needs to change depending on how far the bubble has to move. Currently, a bubble moves at 1,000 pixels per second. So for example, if we want a bubble to move 200 pixels, the duration needs to be set at 200 milliseconds. To handle this variable duration, instead of specifying the CSS transitions in the style sheet, we’ll apply them at runtime with JavaScript.

Setting a CSS transition with jQuery uses the same syntax as setting any other CSS property, but we’ll need to add browser prefixes for property names. Fortunately, we don’t have to write four versions of the same transition for this task. Modernizr can take care of those prefixes for us, which actually makes it easier to create CSS transitions in JavaScript than in a style sheet!

However, not all older browsers support transitions, so inside *ui.js* we’ll first check whether CSS animations are supported and fall back to the jQuery animation if they’re not. Unless you’re sure that CSS transitions are supported in all of the browsers you’re targeting, it’s a good idea to build in a fallback option.

The code for this CSS animation involves three steps:

1.  Add the transition CSS property to the element to tell it how quickly to move and which property to apply the transition to.

2.  Change the `top` and `left` properties to the coordinates we want the bubble to stop at.

3.  Once the bubble has reached its destination, remove the CSS transition definition.

Amend `fireBubble` in *ui.js* as follows:

*ui.js*

```
  var BubbleShoot = window.BubbleShoot || {};
  BubbleShoot.ui = (function($){
    var ui = {
      --*snip*--
      fireBubble : function(bubble,coords,duration){
➊      **var complete = function(){**
➋        **if(bubble.getRow() !== null){**
➌          **bubble.getSprite().css(Modernizr.prefixed("transition"),"");**
            **bubble.getSprite().css({**
              **left : bubble.getCoords().left - ui.BUBBLE_DIMS/2,**
              **top : bubble.getCoords().top - ui.BUBBLE_DIMS/2**
            **});**
          **};**
        **};**
➍      **if(Modernizr.csstransitions){**
➎        **bubble.getSprite().css(Modernizr.prefixed("transition"),"all " +**
            **(duration/1000) + "s linear");**
          **bubble.getSprite().css({**
            **left : coords.x - ui.BUBBLE_DIMS/2,**
            **top : coords.y - ui.BUBBLE_DIMS/2**
          **});**
➏        **setTimeout(complete,duration);**
➐      **}else{**
          bubble.getSprite().animate({
              left : coords.x - ui.BUBBLE_DIMS/2,
              top : coords.y - ui.BUBBLE_DIMS/2
            },
            {
              duration : duration,
              easing : "linear",
              complete : **complete**
            });
        **}**
      },
      --*snip*--
    };
    return ui;
  } )(jQuery);
```

We’ve moved the post-animation function—the one we want jQuery to call once the `animate` call has been completed—into its own named definition ➊ by assigning it to a variable. This function ensures that if the bubble hasn’t disappeared off the screen, it’s finally positioned within the board grid. This function is identical to the previous version in that first we check to see whether the bubble has a row definition ➋. If the row definition is null, the bubble missed the board or caused a popping event. Otherwise, the bubble needs to become part of the main board. In that case, we also remove ➌ the transition definition and move the bubble to its final position. Consequently, if we apply any CSS changes to the bubble in the future, an unwanted transition won’t be applied to them.

When `fireBubble` is called, we check that CSS transitions are supported using Modernizr ➍. If they are supported, we can add the transition CSS to the bubble element ➎. The transition definition will take the form

```
transform: all [duration]s linear
```

`Modernizr.prefixed("transition")` adds any necessary vendor-specific prefixes. We set the transition duration to be the same as the duration passed in but divide it by a thousand to convert from milliseconds to seconds ➎.

Finally, if we did add a transition, we set a timeout ➏ to call `complete` when that transition ends. We don’t need the `setTimeout` call if a browser doesn’t support CSS because, in that case, we’ll use the jQuery `animate` function, which accepts a callback function to run once an animation completes. We need to add the `complete` function as a parameter to that `animate` call ➐, but essentially, the jQuery version of the animation is the same as before.

Refresh the page, fire a bubble, and most likely you’ll see no change in the game from the last time you tested it. But that just means your device could display the jQuery animation we asked it to before at a high enough frame rate that it’s indistinguishable from the CSS version. Behind the scenes, that animation is now being passed off to the graphics processor, if your device has one, so JavaScript doesn’t have to handle the processing load. In games with numerous moving elements, the change you just made could result in a noticeable performance increase.

# Disadvantages of CSS Transitions

If JavaScript has to do so much work to animate an element frame by frame, why not use CSS transitions wherever possible? Although CSS transitions offer a number of benefits, particularly when it comes to smooth animations, their usefulness in games is often limited by a lack of control.

CSS transitions become more cumbersome to compose as you add more animations to a single element. For example, if you want an element to move by 100 pixels over a duration of 1 second and you also resize it by 10 pixels over 2 seconds, you need to specify a different transition for each CSS property. More important, at the end of the movement transition, you’ll need to retain the CSS definition so the resize animation continues, which is especially difficult if you need to move the element again.

A second disadvantage of transitions is that although easing can alter the way an animation appears, movement must be in a straight line. Movement along a curve, as in an animation of a character jumping over something, could be generated by animating over many small straight line segments. But in that case, you may as well use JavaScript for the entire animation.

Once set in motion, CSS transitions are impossible to interrogate and change. The browser handles the transition and updates the element’s position as soon as you set the value in CSS. The element may be rendered halfway to its destination due to the transition, but the DOM will report that it’s already done moving. As a result, it is impossible to interrogate an element for its current position until the animation ends. If you wanted to apply a change in direction, you’d need to perform new calculations and rewrite your CSS transition.

For example, if you tell an element to change its left position from 50 pixels to 250 pixels over 2 seconds, but after 1 second you need to move it to a different screen position, you would first need to calculate where it sits on the screen after 1 second. The DOM would report its left position at 250 pixels, but we know that it’s at the midpoint of an animation, which would put it at 150 pixels in *most* cases. But if you had specified easing along a cubic Bézier curve, the element is unlikely to be at the midpoint and indeed may be quite far from it. You would need to write an equation to calculate the current left coordinate. This example is simpler than most because we stop the element midway, but with any kind of easing applied and at almost any other point along the animation path, calculating where an element might be drawn on the screen is no simple task.

Compare this example to animating with jQuery, in which you can just call the `.stop` method after 1,000 milliseconds to stop an element dead in its tracks. With jQuery, you can even apply a new `animate` method to set a sprite on an entirely new path without waiting for a previous animation to finish. CSS transformations and transitions work well for user-interface manipulation or for relatively simple straight-line movement, but they don’t provide the flexibility we need for a lot of in-game action.

# Summary

You’ve seen how simple and powerful CSS transitions can be, but also how their usefulness can be limited for in-game action. You’ve also taken a brief look at CSS transformations that can be used in combination with transitions to add special effects to buttons or other HTML elements.

One of the main advantages of CSS transitions over JavaScript animation is their rendering speed, but unfortunately they are not easy to work with for anything other than the simplest of animations. In the next chapter, we’ll look at the `canvas` element and see how we can animate games with greater speed and control than DOM-based development has given us.

# Further Practice

1.  Using the CSS transition example in which we animated the New Game button, experiment with some Bézier curve easing. Think about how different values might be useful in game animations.

2.  Create a transformation matrix to flip an element from left to right to make it appear mirrored.

3.  Common 2D CSS transformations include translate, rotate, scale, and skew. Which of these can you reproduce using a matrix transformation, and which can’t you reproduce?