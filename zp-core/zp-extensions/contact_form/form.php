<?php
/**
 * Form for contact_form plugin
 *
 * @package plugins
 */
?>

<form id="mailform" action="<?php echo html_encode(getRequestURI()); ?>" method="post" accept-charset="UTF-8">
	<input type="hidden" id="sendmail" name="sendmail" value="sendmail" />
		<?php if(showOrNotShowField(getOption('contactform_title'))) { ?>
		<p>
			<label for="title"><?php printf(gettext("Title<strong>%s</strong>:"),(checkRequiredField(getOption('contactform_title')))); ?></label>
			<input type="text" id="title" name="title" size="50" value="<?php echo html_encode($mailcontent['title']); ?>"<?php if ($_processing_post) echo ' disabled="disabled"';?> />
		</p>
		<?php } ?>
		<?php if(showOrNotShowField(getOption('contactform_name'))) { ?>
		<p>
			<label for="name"><?php printf(gettext("Name<strong>%s</strong>:"),(checkRequiredField(getOption('contactform_name')))); ?></label>
			<input type="text" id="name" name="name" size="50" value="<?php echo html_encode($mailcontent['name']); ?>"<?php if ($_processing_post) echo ' disabled="disabled"'; ?> />
		</p>
		<?php } ?>
		<p style="display:none;">
			<label for="username">Username:</label>
			<input type="text" id="username" name="username" size="50" value="<?php echo html_encode($mailcontent['honeypot']); ?>"<?php if ($_processing_post) echo ' disabled="disabled"'; ?> />
		</p>
		<?php if(showOrNotShowField(getOption('contactform_company'))) { ?>
		<p>
			<label for="company"><?php printf(gettext("Company<strong>%s</strong>:"),(checkRequiredField(getOption('contactform_company')))); ?></label>
			<input type="text" id="company" name="company" size="50" value="<?php echo html_encode($mailcontent['company']); ?>"<?php if ($_processing_post) echo ' disabled="disabled"'; ?> />
		</p>
		<?php } ?>
		<?php if(showOrNotShowField(getOption('contactform_street'))) { ?>
		<p>
			<label for="street"><?php printf(gettext("Street<strong>%s</strong>:"),(checkRequiredField(getOption('contactform_street')))); ?></label>
			<input type="text" id="street" name="street" size="50" value="<?php echo html_encode($mailcontent['street']); ?>"<?php if ($_processing_post) echo ' disabled="disabled"'; ?> />
		</p>
		<?php } ?>
		<?php if(showOrNotShowField(getOption('contactform_city'))) { ?>
		<p>
			<label for="city"><?php printf(gettext("City<strong>%s</strong>:"),(checkRequiredField(getOption('contactform_city')))); ?></label>
			<input type="text" id="city" name="city" size="50" value="<?php echo html_encode($mailcontent['city']); ?>"<?php if ($_processing_post) echo ' disabled="disabled"'; ?> />
		</p>
		<?php } ?>
		<?php if(showOrNotShowField(getOption('contactform_state'))) { ?>
		<p>
			<label for="state"><?php printf(gettext("State<strong>%s</strong>:"),(checkRequiredField(getOption('contactform_state')))); ?></label>
			<input type="text" id="state" name="state" size="50" value="<?php echo html_encode($mailcontent['city']); ?>"<?php if ($_processing_post) echo ' disabled="disabled"'; ?> />
		</p>
		<?php } ?>
		<?php if(showOrNotShowField(getOption('contactform_country'))) { ?>
		<p>
			<label for="country"><?php printf(gettext("Country<strong>%s</strong>:"),(checkRequiredField(getOption('contactform_country')))); ?></label>
			<input type="text" id="country" name="country" size="50" value="<?php echo html_encode($mailcontent['country']); ?>"<?php if ($_processing_post) echo ' disabled="disabled"'; ?> />
		</p>
		<?php } ?>
		<?php if(showOrNotShowField(getOption('contactform_postal'))) { ?>
		<p>
			<label for="postal"><?php printf(gettext("Postal code<strong>%s</strong>:"),(checkRequiredField(getOption('contactform_postal')))); ?></label>
			<input type="text" id="postal" name="postal" size="50" value="<?php echo html_encode($mailcontent['postal']); ?>"<?php if ($_processing_post) echo ' disabled="disabled"'; ?> />
		</p>
		<?php } ?>
		<?php if(showOrNotShowField(getOption('contactform_email'))) { ?>
		<p>
			<label for="email"><?php printf(gettext("E-Mail<strong>%s</strong>:"),(checkRequiredField(getOption('contactform_email')))); ?></label>
			<input type="text" id="email" name="email" size="50" value="<?php echo html_encode($mailcontent['email']); ?>"<?php if ($_processing_post) echo ' disabled="disabled"'; ?> />
		</p>
		<?php } ?>
		<?php if(showOrNotShowField(getOption('contactform_website'))) { ?>
		<p>
			<label for="website"><?php printf(gettext("Website<strong>%s</strong>:"),(checkRequiredField(getOption('contactform_website')))); ?></label>
			<input type="text" id="website" name="website" size="50" value="<?php echo html_encode($mailcontent['website']); ?>"<?php if ($_processing_post) echo ' disabled="disabled"'; ?> />
		</p>
		<?php } ?>
		<?php if(showOrNotShowField(getOption('contactform_phone'))) { ?>
		<p>
			<label for="phone"><?php printf(gettext("Phone<strong>%s</strong>:"),(checkRequiredField(getOption('contactform_phone')))); ?></label>
			<input type="text" id="phone" name="phone" size="50" value="<?php echo html_encode($mailcontent['phone']); ?>"<?php if ($_processing_post) echo ' disabled="disabled"'; ?> />
		</p>
		<?php
		}
		if(getOption("contactform_captcha") && !$_processing_post) {
			$captcha = $_zp_captcha->getCaptcha();
		?>
		<div>
				<?php if (isset($captcha['inputcode'])) { ?>
					<label for="<?php echo $captcha['inputcode']; ?>"><?php echo gettext("Enter CAPTCHA*"); ?></label> 
					<?php
					} else {
					?>
					<span class="captchalabel">
					<?php echo gettext("Enter CAPTCHA*"); ?>
					</span>
					<?php
					}
					if (isset($captcha['html'])) echo $captcha['html'];
					if (isset($captcha['input'])) echo $captcha['input'];
					if (isset($captcha['hidden'])) echo $captcha['hidden']; 
				?>
			</div>
		<?php } ?>
		<?php if(showOrNotShowField(getOption('contactform_subject'))) { ?>
		<p>
			<label for="subject"><?php printf(gettext("Subject<strong>%s</strong>:"),(checkRequiredField(getOption('contactform_subject')))); ?></label>
			<input type="text" id="subject" name="subject" size="50" value="<?php echo html_encode($mailcontent['subject']); ?>"<?php if ($_processing_post) echo ' disabled="disabled"'; ?> />
		</p>
		<?php } ?>
		<?php if(showOrNotShowField(getOption('contactform_message'))) { ?>
		<p class="mailmessage">
			<label for="message"><?php printf(gettext("Message<strong>%s</strong>:"),(checkRequiredField(getOption('contactform_message')))); ?></label>
			<textarea id="message" name="message" <?php if ($_processing_post) echo ' disabled="disabled"'; ?>><?php echo $mailcontent['message']; ?></textarea>
		</p>
		<?php } ?>
		<?php if (!$_processing_post) { ?>
		<p>
			<input type="submit" class="button buttons" value="<?php echo gettext("Send e-mail"); ?>" />
			<input type="reset" class="button buttons" value="<?php echo gettext("Reset"); ?>" />
		<p>
		<?php } ?>
</form>