document.addEventListener("DOMContentLoaded", () => {

const postContainer = document.getElementById("post-container");
const loader = document.getElementById("loader");

/* Replace later with your own backend API */
const API_URL = "https://jsonplaceholder.typicode.com/posts?_limit=6";

async function fetchPosts(){

try{

const response = await fetch(API_URL);
const posts = await response.json();

loader.style.display = "none";

renderPosts(posts);

}catch(error){

console.error("Backend connection error:",error);
loader.innerText = "Unable to load articles.";

}

}

function renderPosts(posts){

posts.forEach((post,index)=>{

const card = document.createElement("article");
card.classList.add("post-card");

card.style.animationDelay = `${index * 0.1}s`;

const imageUrl = `https://picsum.photos/seed/${post.id}/400/200`;

card.innerHTML = `
<img src="${imageUrl}" class="card-image">

<div class="card-content">

<h3 class="card-title">${post.title.substring(0,40)}...</h3>

<p class="card-excerpt">${post.body.substring(0,90)}...</p>

<a href="/post/${post.id}" class="read-more">Read Full Article →</a>

</div>
`;

postContainer.appendChild(card);

});

}

fetchPosts();

});