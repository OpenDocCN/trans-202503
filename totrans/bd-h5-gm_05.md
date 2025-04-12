# Chapter 4. Translating Game State Changes to the Display

Animation is a powerful visual cue to show players how their actions affect a game. Whenever a player causes the game state to change, you need to display the results. In this chapter, you’ll add code to detect and remove bubble groups, learn more about animating CSS sprites, and implement a nifty exploding effect in jQuery.

At this point, players can fire bubbles at the game board, and those bubbles will become part of the bubble grid. Now, we need to pop groups of matching bubbles when a player fires the correct color at them. When `curBubble` is fired into another bubble and a group of three or more matching bubbles forms, all bubbles in that group should show a popping animation and then be removed from the display and the `Board` object.

We’ll also need to detect and handle any cascading effects caused by popping bubbles. For example, if sets of bubbles are disconnected from the main group when we pop another set, we should destroy the disconnected bubbles in a different way.

# Calculating Groups

The `Board` object contains the row and column information for each bubble in the grid and will determine whether a fired bubble forms a group of three or more when it lands. We’ll add a function to *board.js* that returns all of the bubbles surrounding a given (row,column) position. Then we’ll group them by color and work out which ones to pop.

## Fetching Bubbles

First, we need to retrieve the set of bubbles surrounding the specified coordinates from the board’s `rows` variable. Add the following methods to *board.js* after the `addBubble` method:

*board.js*

```
  var Board = function(){
    var that = this;
    var rows = createLayout();
    this.getRows = function(){ return rows;};
    this.addBubble = function(bubble,coords){
      --*snip*--
    };
➊  **this.getBubbleAt = function(rowNum,colNum){**
      **if(!this.getRows()[rowNum])**
        **return null;**
      **return this.getRows()[rowNum][colNum];**
    **};**
➋  **this.getBubblesAround = function(curRow,curCol){**
      **var bubbles = [];**
      **for(var rowNum = curRow - 1;rowNum <= curRow+1; rowNum++){**
        **for(var colNum =** ➌**curCol-2; colNum <=** ➍**curCol+2; colNum++){**
          **var bubbleAt = that.getBubbleAt(rowNum,colNum);**
          **if(bubbleAt && !(colNum == curCol && rowNum == curRow))**
➎          **bubbles.push(bubbleAt);**
          **};**
        **};**
      **return bubbles;**
    **};**
    return this;
  }
```

The `getBubbleAt` method ➊ takes an input row and column coordinate and returns the bubble at that location. If no bubble exists at that location, it returns `null`. The `getBubblesAround` method ➋ loops through the three relevant rows—the same row, the one above, and the one below—and then examines the surrounding columns, calling `getBubbleAt` for each position. Note that `getBubbleAt` returns `null` for every alternate column entry due to the half-populated row arrays. For this reason, we look at two entries to the left ➌ (`curCol-2`) and two to the right ➍ (`curCol+2`) of the current bubble. No matter whether we start on an odd or an even row, this method should work. We also need to check that a bubble exists at the coordinates we’re examining and that we don’t add the bubble that we’re checking around ➎.

Any bubbles surrounding the fired bubble are pushed into the `bubbles` array and are returned by `getBubblesAround`. Each bubble stores its own coordinates, so we don’t need to sort the array or store position information separately.

## Creating Matching Color Groups

Next, we’ll write a more substantial function called `getGroup` to return groups that are the same color as the first bubble and are connected to that bubble. This recursive function will accept two parameters: a bubble, which sets the starting coordinates and the color (type) definition, and an object, which stores bubbles that are part of the group. The object will store found bubbles in two arrays added as properties: first as a linear array and additionally in an array indexed by row and column. The second array allows us to easily check whether we have already added a bubble to the matching set to avoid adding duplicates. Both arrays are added as properties of an object so we can return both when we call the method. The flowchart in [Figure 4-1](ch04.html#grabbing_a_group_of_connected_bubbles_of "Figure 4-1. Grabbing a group of connected bubbles of the same color") shows an overview of this process.

The function we’ll add to the `Board` class looks like this:

*board.js*

```
var Board = function(){
  var that = this;
  var rows = createLayout();
  this.getRows = function(){ return rows;};
  this.addBubble = function(bubble,coords){
    --*snip*--
  };
  this.getBubbleAt = function(rowNum,colNum){
    --*snip*--
  };
  this.getBubblesAround = function(curRow,curCol){
    --*snip*--
  };
  **this.getGroup = function(bubble,found){**
    **var curRow = bubble.getRow();**
    **if(!found[curRow])**
      **found[curRow] = {};**
    **if(!found.list)**
      **found.list = [];**
    **if(found[curRow][bubble.getCol()]){**
      **return found;**
    **}**
    **found[curRow][bubble.getCol()] = bubble;**
    **found.list.push(bubble);**
    **var curCol = bubble.getCol();**
    **var surrounding = that.getBubblesAround(curRow,curCol);**
    **for(var i=0;i<surrounding.length;i++){**
      **var bubbleAt = surrounding[i];**
      **if(bubbleAt.getType() == bubble.getType()){**
        **found = that.getGroup(bubbleAt,found);**
      **};**
    **};**
    **return found;**
  **};**
  return this;
};
```

Let’s break down this new function and walk through the logic. After we pass in the `bubble` object and `found` object, `getGroup` first checks to see if this bubble was already found.

```
   var curRow = bubble.getRow();
➊ if(!found[curRow])
     found[curRow] = {};
➋ if(!found.list)
     found.list = [];
➌ if(found[curRow][bubble.getCol()]){
     return found;
   }
➍ found[curRow][bubble.getCol()] = bubble;
➎ **found.list.push(bubble);**
```

If the bubble was already found, `getGroup` should return the current unchanged data and stop. If the `found` object doesn’t have an entry for the current row, we need to create an empty array ➊. Then, if the `list` property doesn’t exist, it needs to be created ➋ but only on the initial call to the function. If this bubble was detected previously, we return the found object without adding the bubble again ➌. Otherwise, we track that we’ve looked in this location ➍ and store the bubble in the `found` list ➎.

Next, we retrieve the surrounding bubbles ➏.

```
   var curCol = bubble.getCol();
➏ var surrounding = that.getBubblesAround(curRow,curCol);
```

At most, there should be six, and then we need to check each for a color match:

```
     for(var i=0;i<surrounding.length;i++){
       var bubbleAt = surrounding[i];
➐     if(bubbleAt.getType() == bubble.getType()){
         found = that.getGroup(bubbleAt,found);
       };
     };
➑ return found;
```

If a bubble matches the fired bubble’s color ➐, the function calls itself; `getGroup` adds the checked bubble to the flat array and marks that its coordinates have been checked. The function calls itself again, passing in the newly found bubble and the current data state (with the `found` list). Whatever the result, we’ll return the final value of `found` ➑.

![Grabbing a group of connected bubbles of the same color](httpatomoreillycomsourcenostarchimages2184519.png)

Figure 4-1. Grabbing a group of connected bubbles of the same color

Now we need to call this method when the bubble is fired. In *game.js*, add in the `clickGameScreen` routine:

*game.js*

```
  var clickGameScreen = function(e){
    var angle = BubbleShoot.ui.getBubbleAngle(curBubble.getSprite(),e);
    var duration = 750;
    var distance = 1000;
    var collision = BubbleShoot.CollisionDetector.findIntersection(curBubble,
      board,angle);
    if(collision){
      var coords = {
        x : bubbleCoords.left + distX,
        y : bubbleCoords.top - distY
      };
      duration = Math.round(duration * collision.distToCollision / distance);
      board.addBubble(curBubble,coords);
➊    **var group = board.getGroup(curBubble,{});**
➋    **if(group.list.length >= 3){**
➌      **popBubbles(group.list,duration);**
      **}**
    }else{
      --*snip*--
    };
    BubbleShoot.ui.fireBubble(curBubble,coords,duration);
    curBubble = getNextBubble();
  };
```

When we fetch a group of bubbles with `board.getGroup` ➊, we might end up with a group containing fewer than three bubbles. Because we need to consider only groups of three or more bubbles, we’ll skip any smaller groups ➋. Now we just need to write the routine for popping bubbles ➌!

# Popping Bubbles

We need the game to determine whether a group of bubbles has three or more bubbles, and if so, remove those bubbles. In this section, you’ll implement the JavaScript functions that remove bubble groups and add a fun popping animation with CSS.

## Removing Bubble Groups with JavaScript

We’ll begin by calculating what the board should look like after a group has been popped. When that’s complete, we can update the display and remove any popped bubbles from view. As long as the game state is calculated correctly, you can add animation thereafter. Updating the game state and then writing separate code to display the new state is a useful approach to take throughout game development.

Add a new function called `popBubbles` after `clickGameScreen`:

*game.js*

```
  var BubbleShoot = window.BubbleShoot || {};
  BubbleShoot.Game = (function($){
    var Game = function(){
      --*snip*--
      var clickGameScreen = function(e){
        --*snip*--
      };
      **var popBubbles = function(bubbles,delay){**
➊      **$.each(bubbles,function(){**
          **var bubble = this;**
➋        **board.popBubbleAt(this.getRow(),this.getCol());**
          **setTimeout(function(){**
            **bubble.getSprite().remove();**
          **},delay + 200);**
        **});**
      **};**
    };
    return Game;
  })(jQuery);
```

The `popBubbles` function loops over each `bubble` object in the array we pass it ➊ and tells the board to remove the bubble ➋ by calling `popBubbleAt` (which we’ll write next). Then it waits for `delay + 200` milliseconds to remove the bubble from the DOM to allow time for the animation of firing the bubble to run. As a result, the user can see what’s happened before the screen is updated. The starting value of `delay` is passed in from the fired bubble’s duration—the time it took to travel from its starting point—so bubbles will always disappear 200 milliseconds after the grouping has occurred.

The final piece of code is in *board.js*, where we need to define `popBubbleAt`. Add the following method after the close of the `getGroup` method:

*board.js*

```
var Board = function(){
  --*snip*--
  this.getGroup = function(bubble,found){
    --*snip*--
  };
  **this.popBubbleAt = function(rowNum,colNum){**
    **var row = rows[rowNum];**
    **delete row[colNum];**
  **};**
  return this;
};
```

The `popBubbleAt` method simply removes the entry you pass it from the row/column array.

Reload the game and fire a bubble. When you make a set of three or more bubbles, they should disappear from view. At last, *Bubble Shooter* is starting to look more like a game!

## Popping Animations with CSS

*Moving* sprites around the screen with CSS is one type of animation, but now it’s time to animate sprites in a different way and change how they *look.* This will present players with a visually rewarding popping animation, which will use the other sprite frames we created at the beginning of the book.

The best way to animate a sprite graphic is by changing the position of its background image. Recall that *bubble_sprite_sheet.png* (shown again in [Figure 4-2](ch04.html#four_states_of_the_bubble_spritecomma_as "Figure 4-2. The four states of the bubble sprite, as contained in bubble_sprite_sheet.png") for convenience) contains not only the four bubble types but also four different states for each color.

![The four states of the bubble sprite, as contained in bubble_sprite_sheet.png](httpatomoreillycomsourcenostarchimages2184521.png.jpg)

Figure 4-2. The four states of the bubble sprite, as contained in *bubble_sprite_sheet.png*

We can display a popping animation by showing the four frames in succession, which we’ll do by shifting the background image to the left by 50 pixels at a time.

The game pops only bubbles in groups, but the popping effect won’t be nearly as fun to watch if all the bubbles in a group disappear at once. To make the effect more interesting, we’ll pop the bubbles individually rather than all together. Doing so will require a small change to the `popBubbles` method we just added to *game.js*:

*game.js*

```
  var popBubbles = function(bubbles,delay){
    $.each(bubbles,function(){
      var bubble = this;
      **setTimeout(function(){**
➊      **bubble.animatePop();**
      **},delay);**
      board.popBubbleAt(bubble.getRow(),bubble.getCol());
      setTimeout(function(){
        bubble.getSprite().remove();
      },delay + 200);
➋    **delay += 60;**
    });
  };
```

Here, we call `animatePop` ➊, a new method that we’ll add to `Bubble` to change the bubble’s background image position. The first bubble’s popping animation should start as soon as the fired bubble collides with it. But subsequent pops should be delayed by 60 milliseconds by incrementing `delay` ➋. Add `animatePop` to *bubble.js*.

*bubble.js*

```
  var Bubble = function(row,col,type,sprite){
    --*snip*--
    this.getCoords = function(){
    --*snip*--
    };
    **this.animatePop = function(){**
➊    **var top = type * that.getSprite().height();**
➋    **this.getSprite().css(Modernizr.prefixed("transform"),"rotate(" + (Math.**
        **random() * 360) + "deg)");**
➌    **setTimeout(function(){**
        **that.getSprite().css("background-position","-50px -" + top + "px");**
      **},125);**
      **setTimeout(function(){**
        **that.getSprite().css("background-position","-100px -" + top + "px");**
      **},150);**
      **setTimeout(function(){**
        **that.getSprite().css("background-position","-150px -" + top + "px");**
      **},175);**
➍    **setTimeout(function(){**
        **that.getSprite().remove();**
      **},200);**
    **};**
  };
```

Based on the bubble’s type, `animatePop` calculates ➊ the value representing the top part of the bubble’s `background-position` property. The `type` value tells us what color the bubble should be; we’ll use it to select the appropriate row of popping animation images. Next, using a basic CSS transformation, we add a bit of visual variation ➋ to the animation by rotating the bubble sprite at a random angle to prevent all the popping animations from appearing identical. You’ll see more examples of CSS transformations in [Chapter 5](ch05.html "Chapter 5. CSS Transitions and Transformations"). To stagger the start time of each popping animation, the function makes three delayed calls ➌ that move the `background-position` to the left by 50 pixels.

### Note

*Hard-coding an animation this way is not very scalable, but* Bubble Shooter *has only one sprite with three frames to display. Therefore, we can avoid writing a generic function, which is the reason we use a sequence of `setTimeout` calls instead. When we implement the same animation using `canvas` rendering, you’ll see an example of how to code an animation that is more reusable.*

Finally, `animatePop` removes the sprite’s DOM element ➍ when the animation has finished. Removing the node from the DOM helps with memory management, which would be even more important in a game with more onscreen objects. At approximately 20 frames per second, the resulting animation frame rate is fairly poor. A professional game should have a frame rate of three times that number. But the principle of creating an animation by shifting a background image is the same regardless.

When you reload the page and fire a bubble to make a matching group, you should see a pleasing popping animation. However, after popping numerous bubbles, you may see a side effect of removing bubbles that we need to remedy: a popped group might be the only element holding a set of bubbles of varied colors onto the main board. Currently, these bubbles are left hanging in space and look a bit odd. Because the game design stipulates that these bubbles be removed as well, we’ll do that next.

# Orphaned Groups

Groups of bubbles that have been disconnected from the rest of the board are called *orphans*. For example, in [Figure 4-3](ch04.html#popping_the_red_bubbles_creates_four_orp "Figure 4-3. Popping the red bubbles creates four orphaned bubbles."), popping the boxed group of bubbles would leave four orphaned bubbles hanging in midair. Orphaned sets of bubbles need to be removed by the firing bubble as well. But rather than have them pop in the same way as popped groups, we’ll add a different animation. Orphans will fall off the screen and appear as though they were hanging and had their supports cut. Not only will players recognize that something different has happened, but we also get to experiment with a different animation type. Currently, detecting orphaned groups is not part of the code; so, before we can animate them, we need to find them.

![Popping the red bubbles creates four orphaned bubbles.](httpatomoreillycomsourcenostarchimages2184523.png.jpg)

Figure 4-3. Popping the red bubbles creates four orphaned bubbles.

## Identifying Orphaned Bubbles

We’ll check each bubble and determine whether it’s part of a group that’s connected to any bubbles in the top row. Because the top row is considered to be permanently attached, any bubble that can’t trace a route back to the top row will be identified as part of an orphaned group.

Tracing this route might seem like a problem we haven’t encountered yet; however, we can actually use the already written `getGroup` method and find orphaned sets quite simply. [Figure 4-4](ch04.html#logic_flow_for_determining_the_set_of_or "Figure 4-4. The logic flow for determining the set of orphaned bubbles") shows the process for checking whether a group is part of an orphaned set.

![The logic flow for determining the set of orphaned bubbles](httpatomoreillycomsourcenostarchimages2184525.png.jpg)

Figure 4-4. The logic flow for determining the set of orphaned bubbles

Using this logic, we can reuse the `getGroup` function in step 2\. But to do so, we need to revise the criterion that bubbles must be the same color to form a group.

Let’s change `getGroup` to take a parameter that allows for the selection of nonmatching color groups:

*board.js*

```
  var Board = function(){
    --*snip*--
➊  this.getGroup = function(bubble,found**,differentColor**){
      var curRow = bubble.getRow();
      if(!found[curRow])
        found[curRow] = {};
      if(!found.list)
        found.list = [];
      if(found[curRow][bubble.getCol()]){
        return found;
      }
      found[curRow][bubble.getCol()] = bubble;
      found.list.push(bubble);
      var curCol = bubble.getCol();
      var surrounding = that.getBubblesAround(curRow,curCol);
      for(var i=0;i<surrounding.length;i++){
        var bubbleAt = surrounding[i];
➋      if(bubbleAt.getType() == bubble.getType() **|| differentColor**){
          found = that.getGroup(bubbleAt,found**,differentColor**);
        };
      };
      return found;
    };
  }
```

The function definition now takes an extra parameter ➊. Where `getGroup` is called recursively, it should ignore the type check ➋ if the value is set to `true`, and it passes the input parameter through the recursion chain. With these simple changes, a `getGroup(bubble,{},true)` call should return all bubbles that the passed bubble is connected to regardless of color. Calling `getGroup(bubble,{},false)` or just `getGroup(bubble,{})` should operate the same way as before.

The `findOrphans` function will be a method in the `Board` class and will examine every bubble in the top row, finding the group of bubbles each one connects to. (Initially, every bubble on the board will be in one big group, except the bubble to be fired.) An array of (row,column) values will be populated with false values, and every time a bubble is found, the (row,column) entry will be set to true for that location. At the end of the process, coordinates that contain a bubble but have a value set to `false` in the returned array will be orphaned and removed from the game.

Add the following code to *board.js* after `popBubbleAt`:

*board.js*

```
var Board = function(){
  --*snip*--
  this.popBubbleAt = function(rowNum,colNum){
    --*snip*--
  };
  **this.findOrphans = function(){**
    **var connected = [];**
    **var groups = [];**
    **var rows = that.getRows();**
    **for(var i=0;i<rows.length;i++){**
      **connected[i] = [];**
    **};**
    **for(var i=0;i<rows[0].length;i++){**
      **var bubble = that.getBubbleAt(0,i);**
      **if(bubble && !connected[0][i]){**
        **var group = that.getGroup(bubble,{},true);**
        **$.each(group.list,function(){**
          **connected[this.getRow()][this.getCol()] = true;**
        **});**
      **};**
    **};**
    **var orphaned = [];**
    **for(var i=0;i<rows.length;i++){**
      **for(var j=0;j<rows[i].length;j++){**
        **var bubble = that.getBubbleAt(i,j);**
        **if(bubble && !connected[i][j]){**
          **orphaned.push(bubble);**
        **};**
      **};**
    **};**
    **return orphaned;**
  **};**
  return this;
};
```

Let’s analyze the `findOrphans` function more closely. First, we set up the arrays we need to find orphaned groups.

```
➊ var connected = [];
➋ var groups = [];
   var rows = that.getRows();
   for(var i=0;i<rows.length;i++){
     connected[i] = [];
   };
```

The `connected` array ➊ is a two-dimensional array of rows and columns; it marks the locations of connected bubbles. The `groups` array ➋ will contain a set of all the groups found, which will be a single group if the entire board is connected. Next, we examine each bubble in the top row.

```
for(var i=0;i<rows[0].length;i++){
  var bubble = that.getBubbleAt(0,i);
```

Here, because we’re only interested in bubbles connected to the top row, we loop over just the top row and fetch bubbles to check. When we have a bubble, we can start creating groups.

```
if(bubble && !connected[0][i]){
  var group = that.getGroup(bubble,{},true);
```

If a bubble is present and this space hasn’t already been marked as connected, we build a group. The call to `getGroup` passes `true` as the third parameter (`differentColor`), because we don’t want to restrict connected bubbles by color.

```
      $.each(group.list,function(){
        connected[this.getRow()][this.getCol()] = true;
      });
  };
};
```

Because the bubble being checked is connected via the first row, the entire group is connected; therefore, we mark each entry in the `connected` array with a true flag.

After calling `findOrphans`, we should have an array of connected row and column entries. A list of orphaned bubbles is the final output we want, so we need to create another empty array to hold that list. A single-dimensional array is sufficient because the bubbles store their own coordinates:

```
  var orphaned = [];
  for(var i=0;i<rows.length;i++){
    for(var j=0;j<rows[i].length;j++){
      var bubble = that.getBubbleAt(i,j);
      if(bubble && !connected[i][j]){
        orphaned.push(bubble);
      };
    };
  };
  return orphaned;
};
```

Using this new array, we examine all the rows and columns on the board, checking whether a bubble exists at each space. If a bubble exists but no entry is in the connected grid, it’s an orphan. We then add it to the orphaned list with the call to `orphaned.push(bubble)`. Finally, `findOrphans` returns the array of orphaned bubbles, which should be empty if no orphans exist.

## Dropping Orphaned Bubbles

Now that we can find the groups of bubbles that will be orphaned, we need to call the function and remove any identified orphaned bubbles. Rather than pop, we want the orphaned bubbles to drop, using an animation that occurs after the popping animation has completed. The internal game state will still update instantaneously, because we calculate the outcome as soon as the player has fired the bubble. We add the delay not just to provide a more dramatic effect, but also so players can follow the results of their actions onscreen. If we animated the falling orphaned groups as soon as we knew they would be orphaned, the effect might be lost. In addition, players might be confused as to why bubbles of different colors had disappeared.

In this situation, the benefits of separating game state from display state are apparent. We update the game state instantly, players can fire their next bubble almost immediately without having to wait for completed animations, and the game feels responsive. But in the display state, we make a big deal of this game state change—for effect and to communicate how the player’s actions lead to the final result. The animation approach is very much a game design decision rather than a coding one, but the way we’ve coded the game allows for flexibility.

In *game.js*, add the following after the call to `popBubbles`:

*game.js*

```
  var Game = function(){
    --*snip*--
    var clickGameScreen = function(e){
      --*snip*--
      if(collision){
        --*snip*--
➊      if(group.list.length >= 3){
          popBubbles(group.list,duration);
➋        **var orphans = board.findOrphans();**
➌        **var delay = duration + 200 + 30 * group.list.length;**
➍        **dropBubbles(orphans,delay);**
        };
      }else{
        --*snip*--
      };
      BubbleShoot.ui.fireBubble(curBubble,coords,duration);
      curBubble = getNextBubble();
    };
  };
```

We need to check for new orphans only if bubbles have been popped ➊, because that’s how orphaned groups are formed. We pop bubbles only if a matching group of three or more is created, so if `group.list` is greater than or equal to three, we need to look for orphaned bubbles. As we retrieve the orphans ➋, we calculate a delay ➌ timed to drop bubbles when all the popping has finished. To perform the animation, we need to write `dropBubbles` ➍.

The `dropBubbles` method will drop the bubbles off the screen. Add the following code after the close of the `popBubbles` function in *game.js*:

*game.js*

```
  var Game = function(){
    --*snip*--
    var popBubbles = function(bubbles,delay){
      --*snip*--
    };
    **var dropBubbles = function(**➊**bubbles,delay){**
      **$.each(bubbles,function(){**
        **var bubble = this;**
➋      **board.popBubbleAt(bubble.getRow(),bubble.getCol());**
        **setTimeout(function(){**
➌        **bubble.getSprite().animate({**
            **top : 1000**
          **},1000);**
        **},delay);**
      **});**
    **};**
  };
```

The `dropBubbles` function takes in parameters for the bubbles to drop ➊ (we’ll pass it the array of bubbles returned by `findOrphans`) and a delay. It removes the bubbles from the board ➋ and then animates them as they drop down the screen ➌.

Refresh the game and pop a few groups of bubbles. When you form an orphan group, the bubbles should drop off the screen rather than popping.

# Exploding Bubbles with a jQuery Plug-in

Although dropping bubbles is an animation, it’s not very dramatic. Let’s liven it up and create more of an explosion! We’ll write a jQuery plug-in to control this animation and abstract it from the game system.

To make the orphaned bubbles animation more impressive, we’ll make the bubbles burst outward before dropping down the screen. We’ll do this by assigning a starting momentum to each bubble and then adjusting its speed with some simulated gravity.

Although writing all the code to do this inline inside `dropBubbles` is possible, it would start to clutter the `Game` class with display logic. However, this animation is an ideal candidate for a jQuery plug-in, and the advantage is that we can reuse the code in future projects.

### Note

*For this example, I’ll cover only the most basic principles of writing jQuery plug-ins. You can explore plug-ins in more depth at* [http://learn.jquery.com/plugins/basic-plugin-creation/](http://learn.jquery.com/plugins/basic-plugin-creation/).

Make a new file called *jquery.kaboom.js* in the *_js* folder and add it to the `Modernizr.load` call. The file-naming convention informs others glancing in your *scripts* folder that this file is a jQuery plug-in; they don’t even need to look at the code.

First, we register the method—which we’ll name `kaboom`—by using jQuery’s plug-in format:

*jquery.kaboom.js*

```
(function(jQuery){
  jQuery.fn.kaboom = function(settings)
  {
  };
})(jQuery);
```

We’ll flesh out this code shortly; right now it doesn’t do anything. This function definition is the standard way of registering a new plug-in with jQuery. Its structure enables calls of the form `$(...).kaboom()`, including passing an optional settings parameter.

The call to `kaboom` will be inside `dropBubbles`, so let’s add that call to `dropBubbles` and remove the `animate` calls:

*game.js*

```
var Game = function(){
  --*snip*--
  var popBubbles = function(bubbles,delay){
    --*snip*--
  };
  var dropBubbles = function(bubbles,delay){
    $.each(bubbles,function(){
      var bubble = this;
      board.popBubbleAt(bubble.getRow(),bubble.getCol());
      setTimeout(function(){
        **bubble.getSprite().kaboom();**
      },delay);
    });
    return;
  };
};
```

The `kaboom` method will be called once for each object. This method will also only operate on jQuery objects; as a jQuery plug-in, it will have no knowledge of the game objects and will work only with DOM elements, making the plug-in reusable in future games.

Inside `jquery.fn.kaboom`, we’ll use an array to store all the objects currently being exploded. Every time we call `kaboom`, we’ll add the calling object to that array. When the bubble has finished moving, it should remove itself from the list. By storing everything we want to move in an array, we can run a single `setTimeout` loop and update the position of all falling bubbles at the same time. Consequently, we’ll avoid having multiple `setTimeouts` clamoring for processing power, and the animation should run much more smoothly.

We’ll also add two more components: some default parameters for gravity and the distance we want a bubble to fall before we consider it off the screen and no longer part of the function.

*jquery.kaboom.js*

```
  (function(jQuery){
➊  **var defaults = {**
      **gravity : 1.3,**
      **maxY : 800**
    **};**
➋  **var toMove = [];**
    jQuery.fn.kaboom = function(settings){
    }
  })(jQuery);
```

The default values are `gravity` and `maxY` ➊, and `toMove` ➋ will hold the falling jQuery objects.

At present, nothing happens when `kaboom` is called. The full `jquery.kaboom` plug-in follows:

*jquery.kaboom.js*

```
  (function(jQuery){
    var defaults = {
      gravity : 1.3,
      maxY : 800
    };
    var toMove = [];
➊  **jQuery.fn.kaboom = function(settings){**
      **var config = $.extend({}, defaults, settings);**
      **if(toMove.length == 0){**
        **setTimeout(moveAll,40);**
      **};**
      **var dx = Math.round(Math.random() * 10) – 5;**
      **var dy = Math.round(Math.random() * 5) + 5;**
      **toMove.push({**
        **elm : this,**
        **dx : dx,**
        **dy : dy,**
        **x : this.position().left,**
        **y : this.position().top,**
        **config : config**
      **});**
    **};**
➋  **var moveAll = function(){**
      **var frameProportion = 1;**
      **var stillToMove = [];**
      **for(var i=0;i<toMove.length;i++){**
        **var obj = toMove[i];**
        **obj.x += obj.dx * frameProportion;**
        **obj.y -= obj.dy * frameProportion;**
        **obj.dy -= obj.config.gravity * frameProportion;**
        **if(obj.y < obj.config.maxY){**
          **obj.elm.css({**
            **top : Math.round(obj.y),**
            **left : Math.round(obj.x)**
          **});**
          **stillToMove.push(obj);**
        **}else if(obj.config.callback){**
          **obj.config.callback();**
     **}**
    **};**
    **toMove = stillToMove;**
    **if(toMove.length > 0)**
        **setTimeout(moveAll,40);**
    **};**
  })(jQuery);
```

Two main loops are in this plug-in: `jQuery.fn.kaboom` ➊, which adds new elements to the animation queue, and `moveAll` ➋, which handles the animation.

Let’s look at `jQuery.fn.kaboom` in more detail first:

```
  jQuery.fn.kaboom = function(settings){
➊  var config = $.extend({}, defaults, settings);
➋  if(toMove.length == 0){
      setTimeout(moveAll,40);
    };
➌  var dx = Math.round(Math.random() * 10) - 5;
    var dy = Math.round(Math.random() * 5) + 5;
➍  toMove.push({
      elm : $(this),
      dx : dx,
      dy : dy,
      x : $(this).position().left,
      y : $(this).position().top,
      config : config
    });
  };
```

This function initiates the animation process and is only called once per object (that is, it doesn’t run as part of an animation loop). The function then sets the config options ➊ for this call to `kaboom`. The syntax creates an object with defaults set in the parent definition (the `defaults` variable) and overrides these settings with any found in the object that’s been passed. It also adds any new name/value pairs to the object `kaboom` will act on.

We look in the array `toMove` and, if the array is empty ➋, set a timeout call that runs the animation. Next, values for the initial *x* and *y* velocities are set in `dx` and `dy` ➌. These values are between –5 and 5 pixels horizontally and between 5 and 10 pixels vertically (upward); both have units of pixels per second. We then add a new object to the `toMove` array ➍. The new object contains the jQuery element, its newly created velocity information, the current screen position, and the config options that were specified within this call.

The `jQuery.fn.kaboom` function runs whenever a `$(...).kaboom` call is made. If at least one object is exploding, a timeout containing `moveAll` will be running. Let’s look at what the `moveAll` function does:

```
  var moveAll = function(){
➊  var frameProportion = 1;
➋  var stillToMove = [];
➌  for(var i=0;i<toMove.length;i++){
      var obj = toMove[i];
➍    obj.x += obj.dx * frameProportion;
      obj.y -= obj.dy * frameProportion;
➎    obj.dy -= obj.config.gravity * frameProportion;
➏    if(obj.y < obj.config.maxY){
        obj.elm.css({
          top : Math.round(obj.y),
          left : Math.round(obj.x)
        });
        stillToMove.push(obj);
➐    }else if(obj.config.callback){
        obj.config.callback();
      }
    };
➑  toMove = stillToMove;
    if(toMove.length > 0)
➒    setTimeout(moveAll,40);
  };
```

We assume that `setTimeout` is indeed running every 40 milliseconds because it’s the value we specify ➒; therefore, we count the frame rate as 25 per second ➊. If a computer is underpowered (or just busy using CPU cycles on another operation) and the delay between frames is much slower than 40 milliseconds, this assumption may result in a poor animation quality. Later, you’ll learn how to produce an animation at constant speed regardless of processor power, but the current solution provides the best compatibility in legacy browsers.

After setting the frame rate, `moveAll` creates an empty array ➋ to store any objects that don’t move past the maximum value of *y* by the end of the animation frame. The resulting value here will become the new value for `toMove` to move again on the next frame.

With the setup work done, `moveAll` loops ➌ over each element in the `toMove` array (that is, all the objects currently in the state of exploding; we populated this array in `jQuery.fn.kaboom`) and grabs a reference to each one in the `obj` variable, which is an object with the following properties:

*   `obj.elm` pointing to the jQuery object

*   `dx` and `dy` velocity values

*   *x*- and *y*-coordinates storing the current position

Inside the loop, we change the *x* and *y* values ➍ by a proportion of the object’s *x* and *y* velocities, respectively. This doesn’t affect the bubble’s screen position yet because we haven’t manipulated the DOM element. The function also adds the configured gravity setting to the object’s vertical velocity ➎. Horizontal velocity should remain constant throughout the explosion effect, but the object will accelerate downward to simulate falling. Next, we check ➏ to see if the object has a value of *y* that exceeds the maximum we either configured in defaults or overrode in the call to `kaboom`. If it doesn’t, the position of the screen element is set to the values stored for the current position, and we add the object to the `stillToMove` array. On the other hand, if the object *has* passed the maximum *y* and a callback function was passed as part of the original `kaboom` call, `moveAll` runs ➐ that function. It’s useful to pass a function into an animation and have that function run when the animation is complete.

Finally, we set the new value of `toMove` ➑ to be the contents of `stillToMove` (that is, all the objects that are still falling), and if the array contains at least one element, we set a timeout to call the same function again in another 40 milliseconds ➒.

Now, when you reload the game and create an orphaned group of objects, the kaboom plug-in should make bubbles drop down the screen. Although it works within our game context, you could call it with any valid jQuery selector and produce a similar result. Keep the code handy so you can reuse the effect in future games!

# Summary

Quite a bit of *Bubble Shooter* is in place now. We can fire bubbles that either settle into the grid or pop groups, and we can detect orphaned groups and drop them off the screen. However, the board can get clogged with unpopped bubbles, and that’s a problem we still need to solve. Currently, there’s also no way to start another level or keep track of your score; both are important elements for this type of game. But before we complete some of the other game functionality, we’ll dive into some HTML5 and CSS implementations of the animations we’ve already written.

So far, we’ve achieved the features needed with some fairly traditional HTML, CSS, and JavaScript techniques. For the most part, the game should run smoothly on most computers. In the next chapter, we’ll improve performance by offloading some of the animation work from JavaScript to CSS. The shift will let us take advantage of hardware acceleration when possible, and we’ll even use some pure HTML5 features for smoother animation. We’ll also implement the entire game using `canvas` rendering rather than DOM and CSS, revealing the advantages and the challenges that result using that approach.

# Further Practice

1.  In the exercises in [Chapter 3](ch03.html "Chapter 3. Game Logic"), you changed `createLayout` to generate alternative grid patterns. Test your layouts now with the popping and orphan-dropping code. Does the code work? How do your patterns affect the feel of the game?

2.  Bubble animations currently consist of four frames. Create your own versions of the images and try adding more frames. Use a `for` loop to generate the extra `setTimeout` calls rather than copying and pasting new lines. Experiment with the timeout delays to speed up and slow down the animation and see which values produce the best effect.

3.  The kaboom jQuery plug-in drops the bubbles off the bottom of the screen, but what would happen if you made the bubbles bounce when they hit the bottom? Amend *jquery.kaboom.js* so the bubbles bounce instead of drop off the screen. You’ll need to reverse their `dy` values and scale them down each time they bounce to mimic some of the bounce energy being absorbed; otherwise, they’ll just bounce back to the same height. The bubbles should be removed from the DOM only when they’ve bounced off either the left or the right edge of the screen, so you’ll also need to ensure that the value of `dx` isn’t close to zero, or they’ll never disappear.