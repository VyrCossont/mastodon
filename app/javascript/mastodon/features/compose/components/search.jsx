import React from 'react';
import PropTypes from 'prop-types';
import { defineMessages, injectIntl, FormattedMessage } from 'react-intl';
import Overlay from 'react-overlays/Overlay';
import { searchEnabled } from '../../../initial_state';
import Icon from 'mastodon/components/icon';

const messages = defineMessages({
  placeholder: { id: 'search.placeholder', defaultMessage: 'Search' },
  placeholderSignedIn: { id: 'search.search_or_paste', defaultMessage: 'Search or paste URL' },
});

class SearchPopout extends React.PureComponent {

  render () {
    const extraInformation = searchEnabled ? <FormattedMessage id='search_popout.tips.full_text' defaultMessage='Simple text returns statuses you have written, favourited, boosted, or have been mentioned in, as well as matching usernames, display names, and hashtags.' /> : <FormattedMessage id='search_popout.tips.text' defaultMessage='Simple text returns matching display names, usernames and hashtags' />;
    return (
      <div className='search-popout'>
        <h4><FormattedMessage id='search_popout.search_format' defaultMessage='Advanced search format' /></h4>

        <ul>
          <li><em>#example</em> <FormattedMessage id='search_popout.tips.hashtag' defaultMessage='hashtag' /></li>
          <li><em>@username@domain</em> <FormattedMessage id='search_popout.tips.user' defaultMessage='user' /></li>
          <li><em>URL</em> <FormattedMessage id='search_popout.tips.user' defaultMessage='user' /></li>
          <li><em>URL</em> <FormattedMessage id='search_popout.tips.status' defaultMessage='status' /></li>
        </ul>

        {extraInformation}

        { searchEnabled &&
          <hr />
        }

        { searchEnabled &&
          <h4><FormattedMessage id='search_popout.search_operators' defaultMessage='Additional search operators for statuses and users' /></h4>
        }

        { searchEnabled &&
          <ul>
            <li><em>+term</em> <FormattedMessage id='search_popout.search_operators.include' defaultMessage='require term in results' /></li>
            <li><em>-term</em> <FormattedMessage id='search_popout.search_operators.exclude' defaultMessage='exclude results containing term' /></li>
            <li><em>&quot;John Mastodon&quot;</em> <FormattedMessage id='search_popout.search_operators.phrase' defaultMessage='search for an entire phrase instead of a single word' /></li>
            <li><em>domain:example.org</em> <FormattedMessage id='search_popout.search_operators.domain' defaultMessage='results from a given domain' /></li>
            <li><em>scope:following</em> <FormattedMessage id='search_popout.search_operators.scope.following' defaultMessage='limit search to users that you follow and statuses from them' /></li>
            <li><em>is:bot</em> <FormattedMessage id='search_popout.search_operators.is.bot' defaultMessage='return only automated accounts and statuses from them' /></li>
            <li><em>-is:bot</em> <FormattedMessage id='search_popout.search_operators.is.not_bot' defaultMessage='exclude automated accounts and statuses from them' /></li>
            <li><em>is:reply</em> <FormattedMessage id='search_popout.search_operators.is.reply' defaultMessage='return only statuses that are replies to another status' /></li>
            <li><em>-is:reply</em> <FormattedMessage id='search_popout.search_operators.is.not_reply' defaultMessage='exclude statuses that are replies to another status' /></li>
            <li><em>from:@username@domain</em> <FormattedMessage id='search_popout.search_operators.from' defaultMessage='return only statuses authored by a given user' /></li>
            <li><em>mentions:@username@domain</em> <FormattedMessage id='search_popout.search_operators.mentions' defaultMessage='return only statuses mentioning a given user' /></li>
            <li><em>lang:es</em> <FormattedMessage id='search_popout.search_operators.lang' defaultMessage='return only statuses in the given language' /></li>
            <li><em>has:link</em> <FormattedMessage id='search_popout.search_operators.has.link' defaultMessage='return only statuses that contain links' /></li>
            <li><em>has:media</em> <FormattedMessage id='search_popout.search_operators.has.media' defaultMessage='return only statuses that include images, audio, or video' /></li>
            <li><em>has:poll</em> <FormattedMessage id='search_popout.search_operators.has.poll' defaultMessage='return only statuses that include a poll' /></li>
            <li><em>has:warning</em> <FormattedMessage id='search_popout.search_operators.has.warning' defaultMessage='return only statuses that have a content warning' /></li>
            <li><em>-has:warning</em> <FormattedMessage id='search_popout.search_operators.has.not_warning' defaultMessage='exclude statuses that have a content warning' /></li>
            <li><em>sensitive:yes</em> <FormattedMessage id='search_popout.search_operators.sensitive.yes' defaultMessage='return only statuses that are marked as sensitive content' /></li>
            <li><em>sensitive:no</em> <FormattedMessage id='search_popout.search_operators.sensitive.no' defaultMessage='exclude statuses that are marked as sensitive content' /></li>
            <li><em>before:2022-12-17</em> <FormattedMessage id='search_popout.search_operators.date.before' defaultMessage='search before a given date' /></li>
            <li><em>after:2022-12-17</em> <FormattedMessage id='search_popout.search_operators.date.after' defaultMessage='search after a given date' /></li>
            <li><em>sort:newest</em> <FormattedMessage id='search_popout.search_operators.sort.newest' defaultMessage='show newest results first' /></li>
            <li><em>sort:oldest</em> <FormattedMessage id='search_popout.search_operators.sort.oldest' defaultMessage='show oldest results first' /></li>
            <li><em>cat has:media</em> <FormattedMessage id='search_popout.search_operators.combinations' defaultMessage='operators can be combined with search terms or each other' /></li>
          </ul>
        }
      </div>
    );
  }

}

export default @injectIntl
class Search extends React.PureComponent {

  static contextTypes = {
    router: PropTypes.object.isRequired,
    identity: PropTypes.object.isRequired,
  };

  static propTypes = {
    value: PropTypes.string.isRequired,
    submitted: PropTypes.bool,
    onChange: PropTypes.func.isRequired,
    onSubmit: PropTypes.func.isRequired,
    onClear: PropTypes.func.isRequired,
    onShow: PropTypes.func.isRequired,
    openInRoute: PropTypes.bool,
    intl: PropTypes.object.isRequired,
    singleColumn: PropTypes.bool,
  };

  state = {
    expanded: false,
  };

  setRef = c => {
    this.searchForm = c;
  };

  handleChange = (e) => {
    this.props.onChange(e.target.value);
  };

  handleClear = (e) => {
    e.preventDefault();

    if (this.props.value.length > 0 || this.props.submitted) {
      this.props.onClear();
    }
  };

  handleKeyUp = (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();

      this.props.onSubmit();

      if (this.props.openInRoute) {
        this.context.router.history.push('/search');
      }
    } else if (e.key === 'Escape') {
      document.querySelector('.ui').parentElement.focus();
    }
  };

  handleFocus = () => {
    this.setState({ expanded: true });
    this.props.onShow();

    if (this.searchForm && !this.props.singleColumn) {
      const { left, right } = this.searchForm.getBoundingClientRect();
      if (left < 0 || right > (window.innerWidth || document.documentElement.clientWidth)) {
        this.searchForm.scrollIntoView();
      }
    }
  };

  handleBlur = () => {
    this.setState({ expanded: false });
  };

  findTarget = () => {
    return this.searchForm;
  };

  render () {
    const { intl, value, submitted } = this.props;
    const { expanded } = this.state;
    const { signedIn } = this.context.identity;
    const hasValue = value.length > 0 || submitted;

    return (
      <div className='search'>
        <input
          ref={this.setRef}
          className='search__input'
          type='text'
          placeholder={intl.formatMessage(signedIn ? messages.placeholderSignedIn : messages.placeholder)}
          aria-label={intl.formatMessage(signedIn ? messages.placeholderSignedIn : messages.placeholder)}
          value={value}
          onChange={this.handleChange}
          onKeyUp={this.handleKeyUp}
          onFocus={this.handleFocus}
          onBlur={this.handleBlur}
        />

        <div role='button' tabIndex='0' className='search__icon' onClick={this.handleClear}>
          <Icon id='search' className={hasValue ? '' : 'active'} />
          <Icon id='times-circle' className={hasValue ? 'active' : ''} aria-label={intl.formatMessage(messages.placeholder)} />
        </div>
        <Overlay show={expanded && !hasValue} placement='bottom' target={this.findTarget} popperConfig={{ strategy: 'fixed' }}>
          {({ props, placement }) => (
            <div {...props} style={{ ...props.style, width: 285, zIndex: 2 }}>
              <div className={`dropdown-animation ${placement}`}>
                <SearchPopout />
              </div>
            </div>
          )}
        </Overlay>
      </div>
    );
  }

}
