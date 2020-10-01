using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using WebMVC.Models;

namespace WebMVC.Controllers
{
    public class AccountController : Controller
    {
        // GET: AccountController
        public ActionResult Index()
        {
            var user = User.Identity.IsAuthenticated;
            return View();
        }

        // GET: AccountController/Details/5
        public ActionResult Details(int id)
        {
            return View();
        }

        // GET: AccountController/Create
        public ActionResult Create()
        {
            return View();
        }

        // POST: AccountController/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create(IFormCollection collection)
        {
            try
            {
                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }

        // GET: AccountController/Edit/5
        public ActionResult Edit(int id)
        {
            return View();
        }

        // POST: AccountController/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit(int id, IFormCollection collection)
        {
            try
            {
                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }

        // GET: AccountController/Delete/5
        public ActionResult Delete(int id)
        {
            return View();
        }

        // POST: AccountController/Delete/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Delete(int id, IFormCollection collection)
        {
            try
            {
                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }

        public async Task<ActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return View(typeof(Index));
        }

        public ActionResult Login()
        {
            return View(new LoginModel());
        }

        [HttpPost]
        public async Task<ActionResult> Login(LoginModel model)
        {
            // step1 Create Claims
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Email, model.Email),
                new Claim(ClaimTypes.Role, "Admin")
            };
            // step2: Create ClaimsIdentity
            var claimIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            // step3:
            var authenProperties = new AuthenticationProperties
            {
                IsPersistent = model.RememberMe,

            };

            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimIdentity), authenProperties);
            if (model.RememberMe)
            {
                //Response.Cookies.Append("Email", Convert.ToBase64String(Encoding.ASCII.GetBytes(model.Email)), new CookieOptions
                //{
                //    Expires = DateTimeOffset.UtcNow.AddMinutes(2)
                //});
                //Response.Cookies.Append("PassWord", Convert.ToBase64String(Encoding.ASCII.GetBytes(model.PassWord)), new CookieOptions
                //{
                //    Expires = DateTimeOffset.UtcNow.AddMinutes(2)
                //});

                Response.Cookies.Append("Email", model.Email.Trim(), new CookieOptions
                {
                    Expires = DateTimeOffset.UtcNow.AddMinutes(2)
                });
                Response.Cookies.Append("PassWord", model.PassWord.Trim(), new CookieOptions
                {
                    Expires = DateTimeOffset.UtcNow.AddMinutes(2)
                });

            }
            else
            {
                //
                Response.Cookies.Append("Email", "");
                Response.Cookies.Append("PassWord", "");
            }
            return Redirect("/");
        }
    }
}
